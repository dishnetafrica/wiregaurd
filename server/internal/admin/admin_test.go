package admin

import (
	"context"
	"fmt"
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
	"github.com/dishnetafrica/wiregaurd/server/internal/onboarding"
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

func TestOnboardingPermissionsAndIsolation(t *testing.T) {
	srv, svc := setup(t, nil)
	ctx := context.Background()
	a, _ := svc.CreateCustomer(ctx, provision.NewCustomer{Name: "Customer A", DefaultPorts: []int{3389}})
	b, _ := svc.CreateCustomer(ctx, provision.NewCustomer{Name: "Customer B", DefaultPorts: []int{3389}})

	owner := client(t)
	csrf := login(t, owner, srv.URL, "owner@dishnet.test")
	// Operator/owner records onboarding facts and a note on A.
	res, _ := owner.PostForm(fmt.Sprintf("%s/admin/customers/%d/onboarding", srv.URL, a.ID), url.Values{"csrf": {csrf}, "office_edition": {"home"}, "readiness": {"needs_attention"}, "readiness_note": {"Home edition; advised Pro upgrade"}})
	if res.StatusCode != 303 || strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatalf("onboarding update: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = owner.PostForm(fmt.Sprintf("%s/admin/customers/%d/notes", srv.URL, a.ID), url.Values{"csrf": {csrf}, "note": {"Called Grace about the Home edition SECRET-A-NOTE"}})
	if res.StatusCode != 303 || strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatalf("note: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// Notes containing passwords are refused.
	res, _ = owner.PostForm(fmt.Sprintf("%s/admin/customers/%d/notes", srv.URL, a.ID), url.Values{"csrf": {csrf}, "note": {"office login password: hunter2"}})
	if !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatal("a note with a password must be refused")
	}
	// A's page shows the attention item and the note; B's page shows neither.
	pageA, _ := owner.Get(fmt.Sprintf("%s/admin/customers/%d", srv.URL, a.ID))
	bodyA, _ := io.ReadAll(pageA.Body)
	if !strings.Contains(string(bodyA), "Windows Home") || !strings.Contains(string(bodyA), "SECRET-A-NOTE") || !strings.Contains(string(bodyA), "entered") {
		t.Fatal("A's page missing onboarding attention item or note or source label")
	}
	pageB, _ := owner.Get(fmt.Sprintf("%s/admin/customers/%d", srv.URL, b.ID))
	bodyB, _ := io.ReadAll(pageB.Body)
	if strings.Contains(string(bodyB), "SECRET-A-NOTE") || strings.Contains(string(bodyB), "Home edition; advised") {
		t.Fatal("tenant isolation broken: B's page shows A's note/readiness")
	}
	// Support view: viewer may read, may not write.
	viewer := client(t)
	vcsrf := login(t, viewer, srv.URL, "viewer@dishnet.test")
	if res, _ := viewer.Get(fmt.Sprintf("%s/admin/customers/%d/support", srv.URL, a.ID)); res.StatusCode != 200 {
		t.Fatalf("viewer support view: %d", res.StatusCode)
	}
	if res, _ := viewer.PostForm(fmt.Sprintf("%s/admin/customers/%d/notes", srv.URL, a.ID), url.Values{"csrf": {vcsrf}, "note": {"viewer note"}}); res.StatusCode != 403 {
		t.Fatalf("viewer must not add notes: %d", res.StatusCode)
	}
	if res, _ := viewer.PostForm(fmt.Sprintf("%s/admin/customers/%d/onboarding", srv.URL, a.ID), url.Values{"csrf": {vcsrf}, "office_edition": {"pro"}, "readiness": {"ready"}}); res.StatusCode != 403 {
		t.Fatalf("viewer must not edit onboarding: %d", res.StatusCode)
	}
	// Customers list shows progress and next action per customer.
	list, _ := owner.Get(srv.URL + "/admin/customers")
	bodyL, _ := io.ReadAll(list.Body)
	if !strings.Contains(string(bodyL), "Next action") || !strings.Contains(string(bodyL), "Customer IT contact") {
		t.Fatal("customer list lacks progress/next action")
	}
}

func TestTallyReadinessFormAndClientConfig(t *testing.T) {
	srv, svc := setup(t, nil)
	ctx := context.Background()
	a, _ := svc.CreateCustomer(ctx, provision.NewCustomer{Name: "Customer A", DefaultPorts: []int{3389}})
	owner := client(t)
	csrf := login(t, owner, srv.URL, "owner@dishnet.test")
	form := func(extra url.Values) *http.Response {
		v := url.Values{"csrf": {csrf}, "office_edition": {"pro"}, "readiness": {"ready"}, "concurrent_users": {"1"}, "concurrent_assessment": {"not_needed"}, "tally_company": {"Kampala Traders Ltd"}}
		for k, vals := range extra {
			v[k] = vals
		}
		res, _ := owner.PostForm(fmt.Sprintf("%s/admin/customers/%d/onboarding", srv.URL, a.ID), v)
		return res
	}
	// Acceptance cannot be recorded before all 8 pilot checks are ticked.
	res := form(url.Values{"accepted": {"yes"}, "pilot_check": {"understands", "task"}})
	if !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatal("acceptance with 2/8 checks must be refused")
	}
	// Unknown check keys are refused.
	if res := form(url.Values{"pilot_check": {"bogus"}}); !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatal("unknown check must be refused")
	}
	// All 8 ticked + accepted: stored, page shows the company and the completed checklist.
	all := url.Values{"accepted": {"yes"}}
	for _, pc := range onboardingChecks() {
		all.Add("pilot_check", pc)
	}
	if res := form(all); strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatalf("8/8 accepted refused: %s", res.Header.Get("Location"))
	}
	page, _ := owner.Get(fmt.Sprintf("%s/admin/customers/%d", srv.URL, a.ID))
	body, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(body), "pilot checklist passed (8 of 8)") || !strings.Contains(string(body), "Kampala Traders Ltd") {
		t.Fatal("page lacks completed checklist or company")
	}
	// The Tally company reaches a staff device's config, never an office device's.
	code, _, _ := svc.CreateCode(ctx, provision.NewCode{CustomerID: a.ID, Role: store.RoleClient})
	act, err := svc.Activate(ctx, provision.ActivateRequest{Code: code, PublicKey: "pA7m9Yv4R0uY5C3bb5N1v2xZ9m0KQ+ZxQ4bS4Rj4+xw=", DeviceName: "Laptop", OS: "Windows 11 Pro"})
	if err != nil {
		t.Fatal(err)
	}
	if act.Config.TallyCompany != "Kampala Traders Ltd" {
		t.Fatalf("client config company: %q", act.Config.TallyCompany)
	}
}

func onboardingChecks() []string {
	var keys []string
	for _, pc := range onboarding.PilotChecks {
		keys = append(keys, pc.Key)
	}
	return keys
}
