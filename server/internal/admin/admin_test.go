package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

func setup(t *testing.T, allow []netip.Prefix) (*httptest.Server, *provision.Service) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := provision.New(provision.Config{Endpoint: "x:1"}, db, wg.NewFake(), &firewall.Fake{}, &provision.FakeRouter{}, log)
	_ = svc.EnsurePool(context.Background(), "primary", netip.MustParsePrefix("10.20.0.0/24"), 28)
	for _, a := range []struct{ email, role string }{{"owner@dishnet.test", "owner"}, {"viewer@dishnet.test", "viewer"}} {
		hash, _ := auth.HashPassword("password-123456")
		_ = db.Tx(context.Background(), func(tx *store.Tx) error {
			_, err := tx.InsertAdmin(store.Admin{Email: a.email, PasswordHash: hash, Role: store.AdminRole(a.role)})
			return err
		})
	}
	h, err := New(svc, log, Options{Allowlist: allow, SecureCookies: false})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc
}

func client(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

func login(t *testing.T, c *http.Client, base, email string) string {
	t.Helper()
	res, err := c.PostForm(base+"/admin/login", url.Values{"email": {email}, "password": {"password-123456"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 303 {
		t.Fatalf("login status %d", res.StatusCode)
	}
	res, _ = c.Get(base + "/admin/customers")
	body, _ := io.ReadAll(res.Body)
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		return ""
	}
	return string(m[1])
}

func TestLoginCSRFAndRoles(t *testing.T) {
	srv, _ := setup(t, nil)
	// Unauthenticated: redirected to login.
	c := client(t)
	if res, _ := c.Get(srv.URL + "/admin/customers"); res.StatusCode != 303 {
		t.Fatalf("anon: %d", res.StatusCode)
	}
	// Wrong password.
	if res, _ := c.PostForm(srv.URL+"/admin/login", url.Values{"email": {"owner@dishnet.test"}, "password": {"wrong"}}); res.StatusCode != 401 {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}
	owner := client(t)
	csrf := login(t, owner, srv.URL, "owner@dishnet.test")
	if csrf == "" {
		t.Fatal("no csrf token in page")
	}
	// POST without CSRF is refused.
	res, _ := owner.PostForm(srv.URL+"/admin/customers", url.Values{"name": {"X"}})
	if res.StatusCode != 403 {
		t.Fatalf("missing csrf: %d", res.StatusCode)
	}
	// With CSRF a customer is created.
	res, _ = owner.PostForm(srv.URL+"/admin/customers", url.Values{"csrf": {csrf}, "name": {"Kampala Traders"}, "device_limit": {"5"}, "default_ports": {"3389, 9000"}})
	if res.StatusCode != 303 || !strings.HasPrefix(res.Header.Get("Location"), "/admin/customers/1") {
		t.Fatalf("create customer: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// Generate a code; the plaintext is shown once on the redirect target.
	res, _ = owner.PostForm(srv.URL+"/admin/customers/1/codes", url.Values{"csrf": {csrf}, "role": {"gateway"}, "max_uses": {"1"}})
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "code=DN-") {
		t.Fatalf("code not issued: %s", loc)
	}
	res, _ = owner.Get(srv.URL + loc)
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "shown once") {
		t.Fatal("code reveal missing")
	}
	// Viewer may read but not write.
	viewer := client(t)
	vcsrf := login(t, viewer, srv.URL, "viewer@dishnet.test")
	if res, _ := viewer.Get(srv.URL + "/admin/customers/1"); res.StatusCode != 200 {
		t.Fatalf("viewer read: %d", res.StatusCode)
	}
	if res, _ := viewer.PostForm(srv.URL+"/admin/customers", url.Values{"csrf": {vcsrf}, "name": {"Nope"}}); res.StatusCode != 403 {
		t.Fatalf("viewer write: %d", res.StatusCode)
	}
	if res, _ := viewer.Get(srv.URL + "/admin/admins"); res.StatusCode != 403 {
		t.Fatalf("viewer admins page: %d", res.StatusCode)
	}
	// Security headers present.
	res, _ = owner.Get(srv.URL + "/admin")
	if res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("security headers missing")
	}
}

func TestIPAllowlist(t *testing.T) {
	srv, _ := setup(t, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	res, _ := http.Get(srv.URL + "/admin/login")
	if res.StatusCode != 403 {
		t.Fatalf("loopback should be refused by allowlist, got %d", res.StatusCode)
	}
}
