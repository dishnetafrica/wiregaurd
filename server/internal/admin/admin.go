// Package admin is the server-rendered administrator dashboard. It is
// protected by: HTTPS (terminated by Caddy), an optional source-IP allowlist,
// argon2id passwords, HttpOnly/SameSite session cookies, per-session CSRF
// tokens, role checks and login rate limiting.
package admin

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/onboarding"
	"github.com/dishnetafrica/wiregaurd/server/internal/policy"
	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/ratelimit"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	sessionCookie = "dishnet_admin"
	sessionTTL    = 8 * time.Hour
)

type Handler struct {
	svc        *provision.Service
	db         *store.DB
	log        *slog.Logger
	tmpl       *template.Template
	allow      []netip.Prefix
	trustProxy bool
	loginLimit *ratelimit.Limiter
	secure     bool
	publicURL  string
	deskURL    string
}

type Options struct {
	DeskURL       string         // public address of the web desktop, e.g. https://tally.dishnetuganda.com
	Allowlist     []netip.Prefix // empty = any source
	TrustProxy    bool
	SecureCookies bool   // false only for local dry-run over plain HTTP
	PublicURL     string // e.g. https://vpn.dishnetuganda.com — used to build install links
}

func New(svc *provision.Service, log *slog.Logger, opt Options) (*Handler, error) {
	funcs := template.FuncMap{
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			d := time.Since(t).Round(time.Second)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
			return t.Format("2006-01-02")
		},
		"hasCheck": onboarding.HasCheck,
		"date": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Format("2006-01-02")
		},
		"datetime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Format("2006-01-02 15:04")
		},
		"ports": func(p []int) string {
			s := make([]string, len(p))
			for i, x := range p {
				s[i] = strconv.Itoa(x)
			}
			return strings.Join(s, ", ")
		},
		"mb":     func(b int64) string { return fmt.Sprintf("%.1f MB", float64(b)/1e6) },
		"online": func(t time.Time) bool { return !t.IsZero() && time.Since(t) < 3*time.Minute },
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, db: svc.DB(), log: log, tmpl: tmpl, allow: opt.Allowlist, trustProxy: opt.TrustProxy,
		loginLimit: ratelimit.New(10, 15*time.Minute), secure: opt.SecureCookies, publicURL: strings.TrimRight(opt.PublicURL, "/"), deskURL: strings.TrimRight(opt.DeskURL, "/")}, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", h.gate(h.loginPage))
	mux.HandleFunc("POST /admin/login", h.gate(h.loginSubmit))
	mux.HandleFunc("POST /admin/logout", h.gate(h.requireRole(store.AdminViewer, h.logout)))
	mux.HandleFunc("GET /admin", h.gate(h.requireRole(store.AdminViewer, h.overview)))
	mux.HandleFunc("GET /admin/{$}", h.gate(h.requireRole(store.AdminViewer, h.overview)))
	mux.HandleFunc("GET /admin/customers", h.gate(h.requireRole(store.AdminViewer, h.customers)))
	mux.HandleFunc("POST /admin/customers", h.gate(h.requireRole(store.AdminOperator, h.createCustomer)))
	mux.HandleFunc("GET /admin/customers/{id}", h.gate(h.requireRole(store.AdminViewer, h.customer)))
	mux.HandleFunc("POST /admin/customers/{id}/update", h.gate(h.requireRole(store.AdminOperator, h.updateCustomer)))
	mux.HandleFunc("POST /admin/customers/{id}/status", h.gate(h.requireRole(store.AdminOperator, h.customerStatus)))
	mux.HandleFunc("POST /admin/customers/{id}/extend", h.gate(h.requireRole(store.AdminOperator, h.extendCustomer)))
	mux.HandleFunc("POST /admin/customers/{id}/onboarding", h.gate(h.requireRole(store.AdminOperator, h.updateOnboarding)))
	mux.HandleFunc("POST /admin/customers/{id}/webaccess", h.gate(h.requireRole(store.AdminOperator, h.setWebAccess)))
	mux.HandleFunc("POST /admin/customers/{id}/webusers", h.gate(h.requireRole(store.AdminOperator, h.createWebUser)))
	mux.HandleFunc("POST /admin/webusers/{id}/reset", h.gate(h.requireRole(store.AdminOperator, h.resetWebUser)))
	mux.HandleFunc("POST /admin/webusers/{id}/disable", h.gate(h.requireRole(store.AdminOperator, h.disableWebUser)))
	mux.HandleFunc("POST /admin/webusers/{id}/clear-2fa", h.gate(h.requireRole(store.AdminOperator, h.clearWebUserTOTP)))
	mux.HandleFunc("POST /admin/customers/{id}/notes", h.gate(h.requireRole(store.AdminOperator, h.addNote)))
	mux.HandleFunc("GET /admin/customers/{id}/support", h.gate(h.requireRole(store.AdminViewer, h.supportView)))
	mux.HandleFunc("POST /admin/customers/{id}/codes", h.gate(h.requireRole(store.AdminOperator, h.createCode)))
	mux.HandleFunc("POST /admin/customers/{id}/policies", h.gate(h.requireRole(store.AdminOperator, h.createPolicy)))
	mux.HandleFunc("POST /admin/codes/{id}/revoke", h.gate(h.requireRole(store.AdminOperator, h.revokeCode)))
	mux.HandleFunc("POST /admin/devices/{id}/revoke", h.gate(h.requireRole(store.AdminOperator, h.revokeDevice)))
	mux.HandleFunc("POST /admin/policies/{id}/toggle", h.gate(h.requireRole(store.AdminOperator, h.togglePolicy)))
	mux.HandleFunc("POST /admin/policies/{id}/delete", h.gate(h.requireRole(store.AdminOperator, h.deletePolicy)))
	mux.HandleFunc("GET /admin/requests", h.gate(h.requireRole(store.AdminViewer, h.requests)))
	mux.HandleFunc("POST /admin/requests/{id}/approve", h.gate(h.requireRole(store.AdminOperator, h.approveRequest)))
	mux.HandleFunc("POST /admin/requests/{id}/reject", h.gate(h.requireRole(store.AdminOperator, h.rejectRequest)))
	mux.HandleFunc("GET /admin/jobs", h.gate(h.requireRole(store.AdminViewer, h.jobs)))
	mux.HandleFunc("POST /admin/jobs/reconcile", h.gate(h.requireRole(store.AdminOperator, h.reconcile)))
	mux.HandleFunc("GET /admin/audit", h.gate(h.requireRole(store.AdminViewer, h.audit)))
	mux.HandleFunc("GET /admin/admins", h.gate(h.requireRole(store.AdminOwner, h.admins)))
	mux.HandleFunc("POST /admin/admins", h.gate(h.requireRole(store.AdminOwner, h.createAdmin)))
}

// ---------- access control ----------

type session struct {
	admin store.Admin
	csrf  string
	hash  string
}

type ctxKey struct{}

func sessionFrom(r *http.Request) *session {
	s, _ := r.Context().Value(ctxKey{}).(*session)
	return s
}

func (h *Handler) clientIP(r *http.Request) netip.Addr {
	if h.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if a, err := netip.ParseAddr(strings.TrimSpace(strings.Split(xff, ",")[0])); err == nil {
				return a
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	a, _ := netip.ParseAddr(host)
	return a
}

// gate enforces the source-IP allowlist and security headers.
func (h *Handler) gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if len(h.allow) > 0 {
			ip := h.clientIP(r)
			ok := false
			for _, p := range h.allow {
				if ip.IsValid() && p.Contains(ip) {
					ok = true
					break
				}
			}
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func roleRank(r store.AdminRole) int {
	switch r {
	case store.AdminOwner:
		return 3
	case store.AdminOperator:
		return 2
	case store.AdminViewer:
		return 1
	}
	return 0
}

func (h *Handler) requireRole(min store.AdminRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := h.loadSession(r)
		if s == nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		if roleRank(s.admin.Role) < roleRank(min) {
			h.render(w, r, "error.html", map[string]any{"Message": "Your role does not permit this action."}, http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if !auth.ConstantTimeEqual(r.FormValue("csrf"), s.csrf) {
				h.render(w, r, "error.html", map[string]any{"Message": "Form expired; please go back and try again."}, http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	}
}

func (h *Handler) loadSession(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	hash := auth.HashToken(c.Value)
	var s *session
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		sess, err := tx.GetSession(hash)
		if err != nil || time.Now().After(sess.ExpiresAt) {
			return nil
		}
		a, err := tx.GetAdmin(sess.AdminID)
		if err != nil || a.Disabled {
			return nil
		}
		s = &session{admin: a, csrf: sess.CSRFToken, hash: hash}
		return nil
	})
	return s
}

// ---------- rendering ----------

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any, status int) {
	if data == nil {
		data = map[string]any{}
	}
	if s := sessionFrom(r); s != nil {
		data["Admin"] = s.admin
		data["CSRF"] = s.csrf
		data["IsOperator"] = roleRank(s.admin.Role) >= 2
		data["IsOwner"] = roleRank(s.admin.Role) >= 3
	}
	data["Flash"] = r.URL.Query().Get("flash")
	data["Error"] = r.URL.Query().Get("error")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("template", "name", name, "err", err)
	}
}

func redirectFlash(w http.ResponseWriter, r *http.Request, to, flash string) {
	http.Redirect(w, r, to+"?flash="+template.URLQueryEscaper(flash), http.StatusSeeOther)
}

func redirectErr(w http.ResponseWriter, r *http.Request, to string, err error) {
	http.Redirect(w, r, to+"?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
}

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

// ---------- auth pages ----------

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "login.html", nil, http.StatusOK)
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r).String()
	if !h.loginLimit.Allow(ip) {
		h.render(w, r, "login.html", map[string]any{"Error": "Too many attempts. Try again in 15 minutes."}, http.StatusTooManyRequests)
		return
	}
	email, password := strings.TrimSpace(r.FormValue("email")), r.FormValue("password")
	var admin store.Admin
	ok := false
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		a, err := tx.GetAdminByEmail(email)
		if err == nil && !a.Disabled && auth.VerifyPassword(a.PasswordHash, password) {
			admin, ok = a, true
		}
		return nil
	})
	if !ok {
		h.log.Warn("admin login failed", "email", email, "ip", ip)
		h.render(w, r, "login.html", map[string]any{"Error": "Invalid email or password."}, http.StatusUnauthorized)
		return
	}
	token, hash, err := auth.NewSessionToken()
	if err != nil {
		http.Error(w, "internal", 500)
		return
	}
	csrf, _ := auth.RandomToken()
	if err := h.db.Tx(r.Context(), func(tx *store.Tx) error {
		if err := tx.InsertSession(store.AdminSession{TokenHash: hash, AdminID: admin.ID, CSRFToken: csrf, ExpiresAt: time.Now().Add(sessionTTL)}); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: admin.Email, Action: "admin.login", Target: "dashboard", IP: ip})
	}); err != nil {
		http.Error(w, "internal", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/admin", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	_ = h.db.Tx(r.Context(), func(tx *store.Tx) error { return tx.DeleteSession(s.hash) })
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: h.secure})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// ---------- pages ----------

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		customers, _ := tx.ListCustomers()
		devices, _ := tx.ListAllDevices()
		failed, _ := tx.CountJobs(store.JobFailed)
		pending, _ := tx.CountTrialRequests(store.TrialPending)
		data["PendingRequests"] = pending
		pools, _ := tx.ListPools()
		online, active := 0, 0
		for _, d := range devices {
			if d.Status == store.DeviceActive {
				active++
				if !d.LastHandshakeAt.IsZero() && time.Since(d.LastHandshakeAt) < 3*time.Minute {
					online++
				}
			}
		}
		data["Customers"] = customers
		data["DeviceCount"] = active
		data["Online"] = online
		data["FailedJobs"] = failed
		data["Pools"] = pools
		return nil
	})
	h.render(w, r, "overview.html", data, http.StatusOK)
}

func (h *Handler) customers(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Templates": policy.Templates}
	type row struct {
		store.Customer
		Done, Total int
		Next, Owner string
	}
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		customers, _ := tx.ListCustomers()
		var rows []row
		for _, c := range customers {
			p := h.progress(tx, c)
			rows = append(rows, row{Customer: c, Done: p.Done, Total: p.Total, Next: p.NextAction, Owner: p.NextOwner})
		}
		data["Customers"] = rows
		return nil
	})
	h.render(w, r, "customers.html", data, http.StatusOK)
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("port %q is not a number", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func parseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, errors.New("date must be YYYY-MM-DD")
	}
	return t.Add(24*time.Hour - time.Second).UTC(), nil // end of that day
}

func (h *Handler) createCustomer(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	limit, _ := strconv.Atoi(r.FormValue("device_limit"))
	ports, err := parsePorts(r.FormValue("default_ports"))
	if err != nil {
		redirectErr(w, r, "/admin/customers", err)
		return
	}
	exp, err := parseDate(r.FormValue("expires_at"))
	if err != nil {
		redirectErr(w, r, "/admin/customers", err)
		return
	}
	plan, ok := store.ParsePlan(r.FormValue("plan"))
	if !ok {
		plan = store.PlanTrial
	}
	c, err := h.svc.CreateCustomer(r.Context(), provision.NewCustomer{Name: r.FormValue("name"), Contact: r.FormValue("contact"), DeviceLimit: limit, DefaultPorts: ports, Plan: plan, ExpiresAt: exp, Actor: s.admin.Email})
	if err != nil {
		redirectErr(w, r, "/admin/customers", err)
		return
	}
	redirectFlash(w, r, fmt.Sprintf("/admin/customers/%d", c.ID), "Customer created with block "+c.VPNBlock.String())
}

func (h *Handler) customer(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"Templates": policy.Templates}
	err = h.db.View(r.Context(), func(tx *store.Tx) error {
		c, err := tx.GetCustomer(id)
		if err != nil {
			return err
		}
		devices, _ := tx.ListDevices(id)
		codes, _ := tx.ListCodes(id)
		policies, _ := tx.ListPolicies(id)
		byID := map[int64]store.Device{}
		var gateways []store.Device
		for _, d := range devices {
			byID[d.ID] = d
			if d.Role == store.RoleGateway && d.Status == store.DeviceActive {
				gateways = append(gateways, d)
			}
		}
		type policyRow struct {
			store.AccessPolicy
			From, To string
		}
		var rows []policyRow
		for _, p := range policies {
			to := byID[p.ToDeviceID]
			row := policyRow{AccessPolicy: p, From: "any client", To: to.Name + " (" + to.VPNIP.String() + ")"}
			if to.Status != store.DeviceActive {
				row.To += " revoked"
			}
			if p.FromDeviceID != 0 {
				row.From = byID[p.FromDeviceID].Name
			}
			if p.ToCIDR.IsValid() {
				row.To += " LAN " + p.ToCIDR.String()
			}
			rows = append(rows, row)
		}
		data["Customer"] = c
		data["Devices"] = devices
		data["Codes"] = codes
		data["Policies"] = rows
		data["Gateways"] = gateways
		data["Expired"] = c.Expired(time.Now())
		data["Capacity"] = capacityOf(c)
		data["Progress"] = h.progress(tx, c)
		data["Onboarding"], _ = tx.GetOnboarding(id)
		data["PilotChecks"] = onboarding.PilotChecks
		data["Notes"], _ = tx.ListSupportNotes(id, 20)
		data["WebUsers"], _ = tx.ListCustomerUsers(id)
		data["DeskURL"] = h.deskURL
		data["GuideURL"] = h.publicURL + "/guide"
		return nil
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if pw := r.URL.Query().Get("userpw"); pw != "" {
		data["NewUserPassword"] = pw // shown exactly once, straight from the redirect
		data["NewUserLogin"] = r.URL.Query().Get("userlogin")
	}
	if code := r.URL.Query().Get("code"); code != "" {
		data["NewCode"] = code // shown exactly once, straight from the redirect
		if h.publicURL != "" {
			data["NewLink"] = h.publicURL + "/get/" + code
		}
	}
	if c, ok := data["Customer"].(store.Customer); ok && !c.SubscriptionExpiresAt.IsZero() {
		data["DaysLeft"] = int(time.Until(c.SubscriptionExpiresAt).Hours() / 24)
	}
	h.render(w, r, "customer.html", data, http.StatusOK)
}

func capacityOf(c store.Customer) int {
	n := 1 << (32 - c.VPNBlock.Bits())
	return n - 2
}

func (h *Handler) updateCustomer(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	var c store.Customer
	if err := h.db.View(r.Context(), func(tx *store.Tx) error {
		var err error
		c, err = tx.GetCustomer(id)
		return err
	}); err != nil {
		http.NotFound(w, r)
		return
	}
	exp, err := parseDate(r.FormValue("expires_at"))
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	ports, err := parsePorts(r.FormValue("default_ports"))
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	limit, _ := strconv.Atoi(r.FormValue("device_limit"))
	if limit < 1 || limit > capacityOf(c) {
		redirectErr(w, r, back, fmt.Errorf("device limit must be between 1 and %d", capacityOf(c)))
		return
	}
	if plan, ok := store.ParsePlan(r.FormValue("plan")); ok {
		c.Plan = plan
	}
	c.Name = strings.TrimSpace(r.FormValue("name"))
	c.Contact = strings.TrimSpace(r.FormValue("contact"))
	c.SubscriptionExpiresAt = exp
	c.DefaultPorts = ports
	c.DeviceLimit = limit
	if err := h.svc.UpdateCustomer(r.Context(), c, s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Customer updated")
}

func (h *Handler) customerStatus(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	status := store.CustomerStatus(r.FormValue("status"))
	if status != store.CustomerActive && status != store.CustomerSuspended {
		redirectErr(w, r, back, errors.New("bad status"))
		return
	}
	if err := h.svc.SetCustomerStatus(r.Context(), id, status, s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Customer "+string(status))
}

func (h *Handler) extendCustomer(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	days, _ := strconv.Atoi(r.FormValue("days"))
	paid := r.FormValue("paid") == "yes"
	if err := h.svc.ExtendSubscription(r.Context(), id, days, paid, s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	what := "Trial extended"
	if paid {
		what = "Subscription set as paid"
	}
	redirectFlash(w, r, back, fmt.Sprintf("%s by %d days", what, days))
}

func (h *Handler) createCode(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	role, ok := store.ParseRole(r.FormValue("role"))
	if !ok {
		redirectErr(w, r, back, errors.New("role must be client or gateway"))
		return
	}
	uses, _ := strconv.Atoi(r.FormValue("max_uses"))
	exp, err := parseDate(r.FormValue("expires_at"))
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	code, _, err := h.svc.CreateCode(r.Context(), provision.NewCode{CustomerID: id, Role: role, Label: strings.TrimSpace(r.FormValue("label")), MaxUses: uses, ExpiresAt: exp, Actor: s.admin.Email})
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	http.Redirect(w, r, back+"?code="+template.URLQueryEscaper(code), http.StatusSeeOther)
}

func (h *Handler) revokeCode(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := r.FormValue("back")
	if back == "" {
		back = "/admin/customers"
	}
	if err := h.svc.RevokeCode(r.Context(), id, s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Code revoked")
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := r.FormValue("back")
	if back == "" {
		back = "/admin/customers"
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "revoked by administrator"
	}
	if err := h.svc.RevokeDevice(r.Context(), id, reason, s.admin.Email); err != nil {
		redirectErr(w, r, back, fmt.Errorf("device revoked in database but hub update failed (%v); the reconciler will retry", err))
		return
	}
	redirectFlash(w, r, back, "Device revoked and removed from the hub")
}

func (h *Handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	to, _ := strconv.ParseInt(r.FormValue("to_device_id"), 10, 64)
	from, _ := strconv.ParseInt(r.FormValue("from_device_id"), 10, 64)
	var ports []int
	var err error
	if t := r.FormValue("template"); t != "" && t != "custom" {
		ports = policy.Templates[t]
	} else if ports, err = parsePorts(r.FormValue("ports")); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	var cidr netip.Prefix
	if c := strings.TrimSpace(r.FormValue("to_cidr")); c != "" {
		if cidr, err = netip.ParsePrefix(c); err != nil {
			redirectErr(w, r, back, errors.New("LAN must be a CIDR prefix"))
			return
		}
	}
	proto := store.Proto(r.FormValue("proto"))
	if proto == "" {
		proto = store.ProtoTCP
	}
	_, err = h.svc.CreatePolicy(r.Context(), provision.NewPolicy{CustomerID: id, FromDeviceID: from, ToDeviceID: to, ToCIDR: cidr, Proto: proto, Ports: ports,
		Label: strings.TrimSpace(r.FormValue("label")), AllowSMB: r.FormValue("allow_smb") == "yes", Actor: s.admin.Email})
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Policy added and applied")
}

func (h *Handler) togglePolicy(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := r.FormValue("back")
	if err := h.svc.SetPolicyEnabled(r.Context(), id, r.FormValue("enabled") == "yes", s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Policy updated")
}

func (h *Handler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := r.FormValue("back")
	if err := h.svc.DeletePolicy(r.Context(), id, s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Policy deleted")
}

func (h *Handler) requests(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		data["Requests"], _ = tx.ListTrialRequests(200)
		return nil
	})
	if cid := r.URL.Query().Get("approved"); cid != "" {
		data["Approved"] = map[string]string{"CustomerID": cid, "Gateway": r.URL.Query().Get("gw"), "Client": r.URL.Query().Get("cl"), "GatewayLink": h.publicURL + "/get/" + r.URL.Query().Get("gw"), "ClientLink": h.publicURL + "/get/" + r.URL.Query().Get("cl")}
	}
	h.render(w, r, "requests.html", data, http.StatusOK)
}

func (h *Handler) approveRequest(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	res, err := h.svc.ApproveTrialRequest(r.Context(), id, s.admin.Email)
	if err != nil {
		redirectErr(w, r, "/admin/requests", err)
		return
	}
	// Codes are shown once, via the redirect, exactly like manual code creation.
	http.Redirect(w, r, fmt.Sprintf("/admin/requests?approved=%d&gw=%s&cl=%s", res.Customer.ID, template.URLQueryEscaper(res.GatewayCode), template.URLQueryEscaper(res.ClientCode)), http.StatusSeeOther)
}

func (h *Handler) rejectRequest(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	if err := h.svc.RejectTrialRequest(r.Context(), id, r.FormValue("note"), s.admin.Email); err != nil {
		redirectErr(w, r, "/admin/requests", err)
		return
	}
	redirectFlash(w, r, "/admin/requests", "Request rejected")
}

// progress derives the onboarding view for one customer; only that customer's rows are read.
func (h *Handler) progress(tx *store.Tx, c store.Customer) onboarding.Progress {
	devices, _ := tx.ListDevices(c.ID)
	policies, _ := tx.ListPolicies(c.ID)
	ob, _ := tx.GetOnboarding(c.ID)
	var trial *store.TrialRequest
	if tr, ok, _ := tx.TrialRequestForCustomer(c.ID); ok {
		trial = &tr
	}
	return onboarding.Compute(onboarding.Input{Customer: c, Devices: devices, Policies: policies, Onboarding: ob, Trial: trial, Now: time.Now()})
}

func (h *Handler) updateOnboarding(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	err := h.svc.UpdateOnboarding(r.Context(), id, provision.OnboardingUpdate{
		OfficeEdition: r.FormValue("office_edition"), Readiness: r.FormValue("readiness"), ReadinessNote: r.FormValue("readiness_note"),
		MarkAccepted: r.FormValue("accepted") == "yes", MarkHandover: r.FormValue("handover") == "yes",
		TallyCompany: r.FormValue("tally_company"), ConcurrentUsers: atoiDefault(r.FormValue("concurrent_users"), 1), ConcurrentAssessment: r.FormValue("concurrent_assessment"),
		PilotChecks: r.Form["pilot_check"],
	}, s.admin.Email)
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Onboarding updated")
}

// ---------- web desktop (browser access) ----------

func (h *Handler) setWebAccess(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	if err := h.svc.SetWebAccess(r.Context(), id, r.FormValue("enabled") == "yes", s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Browser access updated")
}

func (h *Handler) createWebUser(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	u, temp, err := h.svc.CreateCustomerUser(r.Context(), id, r.FormValue("login"), r.FormValue("display_name"), s.admin.Email)
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	http.Redirect(w, r, back+"?userlogin="+template.URLQueryEscaper(u.Login)+"&userpw="+template.URLQueryEscaper(temp), http.StatusSeeOther)
}

// webUserBack resolves the customer page for a user id, refusing ids that do not exist.
func (h *Handler) webUserBack(r *http.Request) (store.CustomerUser, string, error) {
	id, _ := pathID(r)
	var u store.CustomerUser
	err := h.db.View(r.Context(), func(tx *store.Tx) error {
		var err error
		u, err = tx.GetCustomerUser(id)
		return err
	})
	return u, fmt.Sprintf("/admin/customers/%d", u.CustomerID), err
}

func (h *Handler) resetWebUser(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	u, back, err := h.webUserBack(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	temp, err := h.svc.ResetCustomerUserPassword(r.Context(), u.ID, s.admin.Email)
	if err != nil {
		redirectErr(w, r, back, err)
		return
	}
	http.Redirect(w, r, back+"?userlogin="+template.URLQueryEscaper(u.Login)+"&userpw="+template.URLQueryEscaper(temp), http.StatusSeeOther)
}

func (h *Handler) disableWebUser(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	u, back, err := h.webUserBack(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := h.svc.SetCustomerUserDisabled(r.Context(), u.ID, r.FormValue("disabled") == "yes", s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "User updated")
}

func (h *Handler) clearWebUserTOTP(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	u, back, err := h.webUserBack(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := h.svc.ClearCustomerUserTOTP(r.Context(), u.ID, s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Two-factor cleared; the user can enrol again")
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func (h *Handler) addNote(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	id, _ := pathID(r)
	back := fmt.Sprintf("/admin/customers/%d", id)
	if err := h.svc.AddSupportNote(r.Context(), id, r.FormValue("note"), s.admin.Email); err != nil {
		redirectErr(w, r, back, err)
		return
	}
	redirectFlash(w, r, back, "Note added")
}

// supportView: everything support needs to diagnose one customer, nothing of any other.
func (h *Handler) supportView(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{}
	err = h.db.View(r.Context(), func(tx *store.Tx) error {
		c, err := tx.GetCustomer(id)
		if err != nil {
			return err
		}
		devices, _ := tx.ListDevices(id)
		jobs, _ := tx.ListJobs(300)
		var failed []store.Job
		for _, j := range jobs {
			if j.CustomerID == id && j.State == store.JobFailed {
				failed = append(failed, j)
			}
		}
		data["Customer"] = c
		data["Devices"] = devices
		data["FailedJobs"] = failed
		data["Progress"] = h.progress(tx, c)
		data["Notes"], _ = tx.ListSupportNotes(id, 50)
		data["Expired"] = c.Expired(time.Now())
		return nil
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "support.html", data, http.StatusOK)
}

func (h *Handler) jobs(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		data["Jobs"], _ = tx.ListJobs(200)
		return nil
	})
	h.render(w, r, "jobs.html", data, http.StatusOK)
}

func (h *Handler) reconcile(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Reconcile(r.Context()); err != nil {
		redirectErr(w, r, "/admin/jobs", err)
		return
	}
	redirectFlash(w, r, "/admin/jobs", "Hub reconciled")
}

func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		data["Entries"], _ = tx.ListAudit(500)
		return nil
	})
	h.render(w, r, "audit.html", data, http.StatusOK)
}

func (h *Handler) admins(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		data["Admins"], _ = tx.ListAdmins()
		return nil
	})
	h.render(w, r, "admins.html", data, http.StatusOK)
}

func (h *Handler) createAdmin(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	role, ok := store.ParseAdminRole(r.FormValue("role"))
	if !ok {
		redirectErr(w, r, "/admin/admins", errors.New("bad role"))
		return
	}
	hash, err := auth.HashPassword(r.FormValue("password"))
	if err != nil {
		redirectErr(w, r, "/admin/admins", err)
		return
	}
	err = h.db.Tx(r.Context(), func(tx *store.Tx) error {
		a, err := tx.InsertAdmin(store.Admin{Email: r.FormValue("email"), PasswordHash: hash, Role: role})
		if err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: s.admin.Email, Action: "admin.create", Target: a.Email, Detail: string(role)})
	})
	if err != nil {
		redirectErr(w, r, "/admin/admins", err)
		return
	}
	redirectFlash(w, r, "/admin/admins", "Administrator created")
}
