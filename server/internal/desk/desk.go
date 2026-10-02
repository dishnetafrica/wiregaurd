// Package desk is the DishNet Web Desktop: a customer signs in with a
// browser, clicks their office computer and gets its Windows desktop (and
// Tally) inside the tab. The hub makes the Remote Desktop connection on the
// customer's behalf over the existing tunnel; staff devices need nothing
// installed.
//
// Security model: the browser never names a target. The hub picks the
// customer's own office computer from the database, so a user of one
// customer can never reach another's. Windows credentials are typed per
// session, held in memory for at most ticketTTL, and never stored or logged.
package desk

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/wwt/guac"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/ratelimit"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

const (
	sessionCookie = "dishnet_desk"
	sessionTTL    = 12 * time.Hour
	ticketTTL     = 90 * time.Second
	issuer        = "DishNet Secure Connect"
)

type Options struct {
	TrustProxy     bool
	SecureCookies  bool
	GuacdAddr      string // e.g. 127.0.0.1:4822
	SupportContact string
	DeskURL        string // e.g. https://tally.dishnetuganda.com (shown to users)
}

// Dialer opens the connection to guacd; tests substitute a fake.
type Dialer func(ctx context.Context) (net.Conn, error)

type Handler struct {
	svc        *provision.Service
	db         *store.DB
	log        *slog.Logger
	tmpl       *template.Template
	opt        Options
	dial       Dialer
	loginLimit *ratelimit.Limiter
	ws         *guac.WebsocketServer

	mu      sync.Mutex
	tickets map[string]ticket
	pending map[string]string // session hash -> TOTP secret awaiting confirmation
}

// ticket is a one-time, short-lived authorisation to open one RDP session.
type ticket struct {
	user     store.CustomerUser
	target   store.Device
	port     int
	username string
	password string
	domain   string
	expires  time.Time
	ip       string
}

type session struct {
	user     store.CustomerUser
	customer store.Customer
	csrf     string
	hash     string
}

type ctxKey struct{}

func New(svc *provision.Service, log *slog.Logger, opt Options) (*Handler, error) {
	funcs := template.FuncMap{
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			d := time.Since(t).Round(time.Minute)
			if d < time.Minute {
				return "just now"
			}
			return d.String() + " ago"
		},
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	h := &Handler{svc: svc, db: svc.DB(), log: log, tmpl: tmpl, opt: opt, loginLimit: ratelimit.New(10, 15*time.Minute), tickets: map[string]ticket{}, pending: map[string]string{}}
	h.dial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", opt.GuacdAddr)
	}
	h.ws = guac.NewWebsocketServer(h.connect)
	return h, nil
}

// SetDialer replaces the guacd dialer (tests).
func (h *Handler) SetDialer(d Dialer) { h.dial = d }

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /desk", h.gate(h.root))
	mux.HandleFunc("GET /desk/{$}", h.gate(h.root))
	mux.HandleFunc("GET /desk/login", h.gate(h.loginPage))
	mux.HandleFunc("POST /desk/login", h.gate(h.loginSubmit))
	mux.HandleFunc("GET /desk/2fa", h.gate(h.auth(h.twoFactorPage, false)))
	mux.HandleFunc("POST /desk/2fa", h.gate(h.auth(h.twoFactorSubmit, false)))
	mux.HandleFunc("POST /desk/logout", h.gate(h.auth(h.logout, false)))
	mux.HandleFunc("GET /desk/home", h.gate(h.auth(h.home, true)))
	mux.HandleFunc("GET /desk/password", h.gate(h.auth(h.passwordPage, true)))
	mux.HandleFunc("POST /desk/password", h.gate(h.auth(h.passwordSubmit, true)))
	mux.HandleFunc("GET /desk/security", h.gate(h.auth(h.securityPage, true)))
	mux.HandleFunc("GET /desk/security/qr.png", h.gate(h.auth(h.securityQR, true)))
	mux.HandleFunc("POST /desk/security/enable", h.gate(h.auth(h.securityEnable, true)))
	mux.HandleFunc("POST /desk/security/disable", h.gate(h.auth(h.securityDisable, true)))
	mux.HandleFunc("GET /desk/office", h.gate(h.auth(h.officePage, true)))
	mux.HandleFunc("POST /desk/office", h.gate(h.auth(h.officeConnect, true)))
	mux.HandleFunc("GET /desk/ws", h.auth(h.ws.ServeHTTP, true)) // websocket: no CSP/frame headers needed
	mux.Handle("GET /desk/static/", http.StripPrefix("/desk/static/", h.static()))
}

func (h *Handler) static() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	fsrv := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		fsrv.ServeHTTP(w, r)
	})
}

// gate sets security headers for every HTML response.
func (h *Handler) gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}

func (h *Handler) clientIP(r *http.Request) string {
	if h.opt.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if a, err := netip.ParseAddr(strings.TrimSpace(strings.Split(xff, ",")[0])); err == nil {
				return a.String()
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func sessionFrom(r *http.Request) *session {
	s, _ := r.Context().Value(ctxKey{}).(*session)
	return s
}

// auth loads the session; requireFull also demands a completed second factor
// and a non-temporary password.
func (h *Handler) auth(next http.HandlerFunc, requireFull bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, pending := h.loadSession(r)
		if s == nil {
			if r.Method == http.MethodPost || strings.HasPrefix(r.URL.Path, "/desk/ws") {
				http.Error(w, "sign in first", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/desk/login", http.StatusSeeOther)
			return
		}
		if requireFull {
			if pending {
				http.Redirect(w, r, "/desk/2fa", http.StatusSeeOther)
				return
			}
			if s.user.MustChangePassword && !strings.HasPrefix(r.URL.Path, "/desk/password") {
				http.Redirect(w, r, "/desk/password?first=1", http.StatusSeeOther)
				return
			}
		}
		if r.Method == http.MethodPost && r.FormValue("csrf") != s.csrf {
			http.Error(w, "form expired, please try again", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	}
}

func (h *Handler) loadSession(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	hash := auth.HashToken(c.Value)
	var s *session
	pending := false
	_ = h.db.View(r.Context(), func(tx *store.Tx) error {
		ds, err := tx.GetDeskSession(hash)
		if err != nil || time.Now().After(ds.ExpiresAt) {
			return nil
		}
		u, err := tx.GetCustomerUser(ds.UserID)
		if err != nil || u.Disabled {
			return nil
		}
		cu, err := tx.GetCustomer(u.CustomerID)
		if err != nil || !cu.WebAccess || !cu.Serviceable(time.Now()) {
			return nil
		}
		s = &session{user: u, customer: cu, csrf: ds.CSRFToken, hash: hash}
		pending = ds.TOTPPending
		return nil
	})
	return s, pending
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any, status int) {
	if data == nil {
		data = map[string]any{}
	}
	if s := sessionFrom(r); s != nil {
		data["User"] = s.user
		data["Customer"] = s.customer
		data["CSRF"] = s.csrf
	}
	data["Support"] = h.opt.SupportContact
	data["DeskURL"] = h.opt.DeskURL
	if _, ok := data["Flash"]; !ok {
		data["Flash"] = r.URL.Query().Get("flash")
	}
	if _, ok := data["Error"]; !ok {
		data["Error"] = r.URL.Query().Get("error")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("desk template", "name", name, "err", err)
	}
}

// ---------- sign-in ----------

func (h *Handler) root(w http.ResponseWriter, r *http.Request) {
	if s, _ := h.loadSession(r); s != nil {
		http.Redirect(w, r, "/desk/home", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/desk/login", http.StatusSeeOther)
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "login.html", nil, http.StatusOK)
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	login := strings.ToLower(strings.TrimSpace(r.FormValue("login")))
	if !h.loginLimit.Allow(ip) || !h.loginLimit.Allow("login:"+login) {
		h.render(w, r, "login.html", map[string]any{"Error": "Too many attempts. Please wait 15 minutes and try again."}, http.StatusTooManyRequests)
		return
	}
	u, _, err := h.svc.AuthenticateCustomerUser(r.Context(), login, r.FormValue("password"), ip)
	if err != nil {
		msg := "Wrong login or password."
		var denied *provision.DeniedError
		switch {
		case errors.Is(err, provision.ErrUserDisabled), errors.Is(err, provision.ErrNoWebAccess):
			msg = err.Error()
		case errors.As(err, &denied):
			msg = "Your DishNet subscription is " + string(denied.Reason) + ". Please contact DishNet."
		}
		h.render(w, r, "login.html", map[string]any{"Error": msg, "Login": login}, http.StatusUnauthorized)
		return
	}
	token, hash, err := auth.NewSessionToken()
	if err != nil {
		http.Error(w, "internal", 500)
		return
	}
	csrf, _ := auth.RandomToken()
	if err := h.db.Tx(r.Context(), func(tx *store.Tx) error {
		return tx.InsertDeskSession(store.DeskSession{TokenHash: hash, UserID: u.ID, CSRFToken: csrf, TOTPPending: u.TOTPSecret != "", ExpiresAt: time.Now().Add(sessionTTL), IP: ip})
	}); err != nil {
		http.Error(w, "internal", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/desk", HttpOnly: true, Secure: h.opt.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	if u.TOTPSecret != "" {
		http.Redirect(w, r, "/desk/2fa", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/desk/home", http.StatusSeeOther)
}

func (h *Handler) twoFactorPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "twofa.html", nil, http.StatusOK)
}

func (h *Handler) twoFactorSubmit(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	if !h.loginLimit.Allow("2fa:" + s.user.Login) {
		h.render(w, r, "twofa.html", map[string]any{"Error": "Too many attempts. Please wait 15 minutes."}, http.StatusTooManyRequests)
		return
	}
	if !auth.VerifyTOTP(s.user.TOTPSecret, r.FormValue("code"), time.Now()) {
		h.render(w, r, "twofa.html", map[string]any{"Error": "That code is not valid. Open your authenticator app and try the current code."}, http.StatusUnauthorized)
		return
	}
	_ = h.db.Tx(r.Context(), func(tx *store.Tx) error { return tx.SetDeskSessionVerified(s.hash) })
	http.Redirect(w, r, "/desk/home", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	_ = h.db.Tx(r.Context(), func(tx *store.Tx) error { return tx.DeleteDeskSession(s.hash) })
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/desk", MaxAge: -1, HttpOnly: true, Secure: h.opt.SecureCookies})
	http.Redirect(w, r, "/desk/login?flash=Signed+out", http.StatusSeeOther)
}

// ---------- home, password, security ----------

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	data := map[string]any{}
	t, err := h.svc.OfficeTarget(r.Context(), s.customer.ID)
	if err == nil {
		data["Office"] = t.Device
		data["OfficeOnline"] = t.Online
	} else {
		data["NoOffice"] = true
	}
	h.render(w, r, "home.html", data, http.StatusOK)
}

func (h *Handler) passwordPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "password.html", map[string]any{"First": r.URL.Query().Get("first") == "1"}, http.StatusOK)
}

func (h *Handler) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	next, again := r.FormValue("new"), r.FormValue("again")
	if next != again {
		h.render(w, r, "password.html", map[string]any{"Error": "The two new passwords do not match."}, http.StatusBadRequest)
		return
	}
	if err := h.svc.ChangeCustomerUserPassword(r.Context(), s.user.ID, r.FormValue("current"), next); err != nil {
		h.render(w, r, "password.html", map[string]any{"Error": err.Error()}, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/desk/home?flash=Password+changed", http.StatusSeeOther)
}

func (h *Handler) securityPage(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	data := map[string]any{"Enabled": s.user.TOTPSecret != ""}
	if s.user.TOTPSecret == "" {
		h.mu.Lock()
		secret, ok := h.pending[s.hash]
		if !ok {
			secret, _ = auth.NewTOTPSecret()
			h.pending[s.hash] = secret
		}
		h.mu.Unlock()
		data["Secret"] = secret
	}
	h.render(w, r, "security.html", data, http.StatusOK)
}

func (h *Handler) securityQR(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	h.mu.Lock()
	secret, ok := h.pending[s.hash]
	h.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	png, err := qrcode.Encode(auth.TOTPURI(issuer, s.user.Login, secret), qrcode.Medium, 220)
	if err != nil {
		http.Error(w, "qr", 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (h *Handler) securityEnable(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	h.mu.Lock()
	secret, ok := h.pending[s.hash]
	h.mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/desk/security?error=Start+again", http.StatusSeeOther)
		return
	}
	if err := h.svc.EnableCustomerUserTOTP(r.Context(), s.user.ID, secret, r.FormValue("code")); err != nil {
		http.Redirect(w, r, "/desk/security?error="+template.URLQueryEscaper("That code is not valid. Scan the QR code again and enter the current code."), http.StatusSeeOther)
		return
	}
	h.mu.Lock()
	delete(h.pending, s.hash)
	h.mu.Unlock()
	http.Redirect(w, r, "/desk/security?flash=Two-factor+sign-in+is+on", http.StatusSeeOther)
}

func (h *Handler) securityDisable(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	if err := h.svc.DisableCustomerUserTOTP(r.Context(), s.user.ID, r.FormValue("code")); err != nil {
		http.Redirect(w, r, "/desk/security?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/desk/security?flash=Two-factor+sign-in+is+off", http.StatusSeeOther)
}

// ---------- office computer ----------

func (h *Handler) officePage(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	t, err := h.svc.OfficeTarget(r.Context(), s.customer.ID)
	if err != nil {
		http.Redirect(w, r, "/desk/home?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	h.render(w, r, "office.html", map[string]any{"Office": t.Device, "OfficeOnline": t.Online}, http.StatusOK)
}

// officeConnect takes the Windows credentials for this one session, issues a
// one-time ticket and shows the viewer. The credentials never touch the
// database or the logs.
func (h *Handler) officeConnect(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	t, err := h.svc.OfficeTarget(r.Context(), s.customer.ID)
	if err != nil {
		http.Redirect(w, r, "/desk/home?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("winuser"))
	password := r.FormValue("winpass")
	if username == "" || password == "" {
		h.render(w, r, "office.html", map[string]any{"Office": t.Device, "OfficeOnline": t.Online, "Error": "Type the Windows user name and password of the office computer."}, http.StatusBadRequest)
		return
	}
	domain := ""
	if i := strings.Index(username, `\`); i > 0 { // DOMAIN\user or PCNAME\user
		domain, username = username[:i], username[i+1:]
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "internal", 500)
		return
	}
	id := hex.EncodeToString(raw)
	h.mu.Lock()
	now := time.Now()
	for k, tk := range h.tickets {
		if now.After(tk.expires) {
			delete(h.tickets, k)
		}
	}
	h.tickets[id] = ticket{user: s.user, target: t.Device, port: t.Port, username: username, password: password, domain: domain, expires: now.Add(ticketTTL), ip: h.clientIP(r)}
	h.mu.Unlock()
	h.render(w, r, "viewer.html", map[string]any{"Office": t.Device, "Ticket": id}, http.StatusOK)
}

// connect is called by the WebSocket server once the browser opens the
// tunnel. It redeems the ticket (one use), checks it belongs to the signed-in
// user, and performs the guacd handshake with parameters chosen here.
func (h *Handler) connect(r *http.Request) (guac.Tunnel, error) {
	s := sessionFrom(r)
	if s == nil {
		return nil, errors.New("no session")
	}
	q := r.URL.Query()
	h.mu.Lock()
	tk, ok := h.tickets[q.Get("ticket")]
	delete(h.tickets, q.Get("ticket"))
	h.mu.Unlock()
	if !ok || time.Now().After(tk.expires) || tk.user.ID != s.user.ID {
		h.log.Warn("web desktop: invalid ticket", "user", s.user.Login, "ip", h.clientIP(r))
		return nil, errors.New("ticket invalid or expired")
	}
	width, height, dpi := atoiDefault(q.Get("width"), 1280, 640, 4096), atoiDefault(q.Get("height"), 800, 400, 4096), atoiDefault(q.Get("dpi"), 96, 72, 192)

	cfg := guac.NewGuacamoleConfiguration()
	cfg.Protocol = "rdp"
	cfg.Parameters = map[string]string{
		"hostname":              tk.target.VPNIP.String(),
		"port":                  strconv.Itoa(tk.port),
		"username":              tk.username,
		"password":              tk.password,
		"domain":                tk.domain,
		"security":              "any",
		"ignore-cert":           "true",
		"resize-method":         "display-update",
		"disable-audio":         "true",
		"enable-wallpaper":      "false",
		"enable-theming":        "true",
		"enable-font-smoothing": "true",
		"client-name":           "DishNet Web Desktop",
		"timezone":              "Africa/Kampala",
	}
	cfg.OptimalScreenWidth, cfg.OptimalScreenHeight, cfg.OptimalResolution = width, height, dpi
	cfg.ImageMimetypes = []string{"image/png", "image/jpeg", "image/webp"}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	conn, err := h.dial(ctx)
	if err != nil {
		h.svc.RecordDeskConnect(r.Context(), s.user, tk.target, tk.ip, "guacd unreachable")
		h.log.Error("web desktop: guacd dial failed", "err", err)
		return nil, err
	}
	stream := guac.NewStream(conn, guac.SocketTimeout)
	if err := stream.Handshake(cfg); err != nil {
		_ = conn.Close()
		h.svc.RecordDeskConnect(r.Context(), s.user, tk.target, tk.ip, "handshake failed: "+err.Error())
		return nil, err
	}
	h.svc.RecordDeskConnect(r.Context(), s.user, tk.target, tk.ip, fmt.Sprintf("session started %dx%d", width, height))
	return guac.NewSimpleTunnel(stream), nil
}

func atoiDefault(s string, def, min, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < min || n > max {
		return def
	}
	return n
}
