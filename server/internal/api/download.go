package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/ratelimit"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

// Installer download: GET /get/<activation code> serves the Windows installer
// with the code embedded in the file name, so the app can activate itself on
// first run. The code is NOT consumed by downloading; it is validated so a
// stale link gives a clear message instead of a useless download.
type Downloads struct {
	svc       svcDB
	installer string // path to the cached installer exe
	byIP      *ratelimit.Limiter
	log       logger
}

type svcDB interface {
	DB() *store.DB
}

type logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}

func NewDownloads(svc svcDB, installerPath string, log logger) *Downloads {
	return &Downloads{svc: svc, installer: installerPath, byIP: ratelimit.New(20, 10*time.Minute), log: log}
}

func (d *Downloads) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /get/{code}", d.get)
	mux.HandleFunc("GET /get/{$}", func(w http.ResponseWriter, r *http.Request) {
		d.page(w, http.StatusNotFound, "Missing link", "This download link is incomplete. Please use the full link DishNet sent you.")
	})
}

// InstallerFileName is what the browser saves; the app parses the code back out of it.
func InstallerFileName(code string) string { return "DishNetSecureConnect-Setup-" + code + ".exe" }

func (d *Downloads) get(w http.ResponseWriter, r *http.Request) {
	ip := clientIPOf(r)
	if !d.byIP.Allow(ip) {
		d.page(w, http.StatusTooManyRequests, "Too many downloads", "Please wait a few minutes and try again.")
		return
	}
	code, err := auth.NormaliseCode(r.PathValue("code"))
	if err != nil {
		d.page(w, http.StatusNotFound, "Invalid link", "This download link is not valid. Please check the link DishNet sent you.")
		return
	}
	var ac store.ActivationCode
	var cust store.Customer
	err = d.svc.DB().View(r.Context(), func(tx *store.Tx) error {
		var err error
		if ac, err = tx.GetCodeByHash(auth.HashCode(code)); err != nil {
			return err
		}
		cust, err = tx.GetCustomer(ac.CustomerID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		d.log.Warn("installer download with unknown code", "ip", ip)
		d.page(w, http.StatusNotFound, "Invalid link", "This download link is not valid. Please check the link DishNet sent you.")
		return
	}
	if err != nil {
		d.page(w, http.StatusInternalServerError, "Temporary problem", "Please try again in a few minutes.")
		return
	}
	now := time.Now()
	switch {
	case !ac.RevokedAt.IsZero():
		d.page(w, http.StatusGone, "Link cancelled", "This install link was cancelled by DishNet. Please ask for a new one.")
		return
	case !ac.ExpiresAt.IsZero() && !now.Before(ac.ExpiresAt):
		d.page(w, http.StatusGone, "Link expired", "This install link has expired. Please ask DishNet for a new one.")
		return
	case ac.Uses >= ac.MaxUses:
		d.page(w, http.StatusGone, "Link already used", "All devices for this link have been set up. Ask DishNet for a new link to add another computer.")
		return
	case !cust.Serviceable(now):
		d.page(w, http.StatusForbidden, "Account not active", "Your DishNet account is suspended or expired. Please contact DishNet.")
		return
	}
	f, err := os.Open(d.installer)
	if err != nil {
		d.log.Warn("installer file missing", "path", d.installer)
		d.page(w, http.StatusServiceUnavailable, "Installer not available", "The installer is being updated. Please try again in a few minutes.")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	_ = d.svc.DB().Tx(r.Context(), func(tx *store.Tx) error {
		return tx.Audit(store.AuditEntry{ActorType: "device", ActorID: "download", Action: "installer.download", Target: fmt.Sprintf("code:%d", ac.ID), Detail: fmt.Sprintf("customer=%d ua=%s", cust.ID, clip(r.UserAgent(), 80)), IP: ip})
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+InstallerFileName(code)+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, InstallerFileName(code), st.ModTime(), f)
}

func (d *Downloads) page(w http.ResponseWriter, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DishNet Secure Connect</title>
<style>body{font-family:system-ui,sans-serif;background:#f7f7f8;margin:0;padding:40px 16px;color:#1f2328}.c{max-width:480px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:24px}.b{color:#d7262d;font-weight:800;font-size:20px}.m{color:#6b7280}</style></head>
<body><div class="c"><div class="b">DishNet Secure Connect</div><h2>%s</h2><p class="m">%s</p></div></body></html>`, htmlEscape(title), htmlEscape(msg))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func clientIPOf(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
