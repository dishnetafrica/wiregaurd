package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

func TestInstallLinkServesInstallerWithCodeInName(t *testing.T) {
	srv, svc, c := setup(t)
	installer := filepath.Join(t.TempDir(), "setup.exe")
	os.WriteFile(installer, []byte("MZ fake installer"), 0o644)
	mux := http.NewServeMux()
	NewDownloads(svc, installer, slogDiscard()).Register(mux)
	dl := newTestServer(t, mux)

	code, _, _ := svc.CreateCode(context.Background(), provision.NewCode{CustomerID: c.ID, Role: store.RoleClient, MaxUses: 3})
	res, err := http.Get(dl.URL + "/get/" + strings.ToLower(code))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	want := `attachment; filename="DishNetSecureConnect-Setup-` + code + `.exe"`
	if cd := res.Header.Get("Content-Disposition"); cd != want {
		t.Fatalf("content-disposition %q, want %q", cd, want)
	}
	// Downloading does not consume the code.
	_ = svc.DB().View(context.Background(), func(tx *store.Tx) error {
		codes, _ := tx.ListCodes(c.ID)
		if codes[0].Uses != 0 {
			t.Fatalf("download consumed the code: uses=%d", codes[0].Uses)
		}
		return nil
	})
	_ = srv

	// Unknown / malformed links are 404 pages, not downloads.
	for _, bad := range []string{"/get/DN-AAAA-AAAA-AAAA-AAAA", "/get/hello", "/get/"} {
		r, _ := http.Get(dl.URL + bad)
		if r.StatusCode != 404 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d %s", bad, r.StatusCode, r.Header.Get("Content-Type"))
		}
		r.Body.Close()
	}
	// Fully used code -> 410.
	one, _, _ := svc.CreateCode(context.Background(), provision.NewCode{CustomerID: c.ID, Role: store.RoleClient, MaxUses: 1})
	if _, err := svc.Activate(context.Background(), provision.ActivateRequest{Code: one, PublicKey: pub(t)}); err != nil {
		t.Fatal(err)
	}
	if r, _ := http.Get(dl.URL + "/get/" + one); r.StatusCode != 410 {
		t.Fatalf("used code: %d", r.StatusCode)
	}
	// Missing installer file -> 503 with a friendly page.
	os.Remove(installer)
	if r, _ := http.Get(dl.URL + "/get/" + code); r.StatusCode != 503 {
		t.Fatalf("missing installer: %d", r.StatusCode)
	}
}

func TestTrialDefaultsAndExtension(t *testing.T) {
	_, svc, _ := setup(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })

	c, err := svc.CreateCustomer(ctx, provision.NewCustomer{Name: "Trial Co"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Plan != store.PlanTrial || !c.SubscriptionExpiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("new customer should be a 30-day trial, got plan=%s expires=%s", c.Plan, c.SubscriptionExpiresAt)
	}
	code, _, _ := svc.CreateCode(ctx, provision.NewCode{CustomerID: c.ID, Role: store.RoleClient})
	res, err := svc.Activate(ctx, provision.ActivateRequest{Code: code, PublicKey: pub(t)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.Plan != "trial" || res.Config.ExpiresAt == "" {
		t.Fatalf("config should carry plan + expiry: %+v", res.Config)
	}

	// Trial ends: device is denied with reason "expired".
	now = now.Add(31 * 24 * time.Hour)
	_ = svc.Reconcile(ctx)
	_, err = svc.ConfigFor(ctx, res.Device.ID)
	var denied *provision.DeniedError
	if !asDenied(err, &denied) || denied.Reason != provision.DeniedExpired {
		t.Fatalf("want expired, got %v", err)
	}

	// Admin clicks "Mark paid: +30 days": access resumes and the plan is paid.
	if err := svc.ExtendSubscription(ctx, c.ID, 30, true, "admin"); err != nil {
		t.Fatal(err)
	}
	cfg, err := svc.ConfigFor(ctx, res.Device.ID)
	if err != nil {
		t.Fatalf("after extension: %v", err)
	}
	if cfg.Plan != "paid" || cfg.ConfigVersion <= res.Config.ConfigVersion {
		t.Fatalf("plan=%s version %d -> %d", cfg.Plan, res.Config.ConfigVersion, cfg.ConfigVersion)
	}
	// Extension counts from now when already expired (not from the old date).
	_ = svc.DB().View(ctx, func(tx *store.Tx) error {
		cc, _ := tx.GetCustomer(c.ID)
		if !cc.SubscriptionExpiresAt.Equal(now.Add(30 * 24 * time.Hour)) {
			t.Fatalf("expiry %s, want now+30d", cc.SubscriptionExpiresAt)
		}
		return nil
	})
	// Unlimited plan has no expiry; paid plan without a date is refused.
	if _, err := svc.CreateCustomer(ctx, provision.NewCustomer{Name: "Paid no date", Plan: store.PlanPaid}); err == nil {
		t.Fatal("paid plan without expiry must be refused")
	}
	u, err := svc.CreateCustomer(ctx, provision.NewCustomer{Name: "Forever", Plan: store.PlanUnlimited})
	if err != nil || !u.SubscriptionExpiresAt.IsZero() {
		t.Fatalf("unlimited: %v %v", err, u.SubscriptionExpiresAt)
	}
}

// ---- helpers ----

func slogDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func asDenied(err error, target **provision.DeniedError) bool { return errors.As(err, target) }
