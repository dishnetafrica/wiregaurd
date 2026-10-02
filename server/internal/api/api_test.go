package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

func setup(t *testing.T) (*httptest.Server, *provision.Service, store.Customer) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := provision.New(provision.Config{Endpoint: "165.227.89.92:51820", HubAddresses: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}, db, wg.NewFake(), &firewall.Fake{}, &provision.FakeRouter{}, log)
	if err := svc.EnsurePool(context.Background(), "primary", netip.MustParsePrefix("10.20.0.0/24"), 28); err != nil {
		t.Fatal(err)
	}
	c, err := svc.CreateCustomer(context.Background(), provision.NewCustomer{Name: "API Co", DefaultPorts: []int{3389}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(svc, log, false).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, c
}

func post(t *testing.T, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	return res, out
}

func get(t *testing.T, url, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	return res, out
}

func pub(t *testing.T) string {
	k, _ := wgtypes.GeneratePrivateKey()
	return k.PublicKey().String()
}

func TestActivateThenConfigAndRevocation(t *testing.T) {
	srv, svc, c := setup(t)
	ctx := context.Background()
	gwCode, _, _ := svc.CreateCode(ctx, provision.NewCode{CustomerID: c.ID, Role: store.RoleGateway})
	res, body := post(t, srv.URL+"/api/v1/activate", "", map[string]any{"code": gwCode, "public_key": pub(t), "device_name": "Office", "os": "Windows Server 2022", "client_version": "0.1"})
	if res.StatusCode != 201 {
		t.Fatalf("gateway activate: %d %v", res.StatusCode, body)
	}
	clCode, _, _ := svc.CreateCode(ctx, provision.NewCode{CustomerID: c.ID, Role: store.RoleClient})
	// Lower-case, un-dashed input must be accepted.
	loose := bytes.ToLower([]byte(clCode))
	loose = bytes.ReplaceAll(loose, []byte("-"), []byte(""))
	res, body = post(t, srv.URL+"/api/v1/activate", "", map[string]any{"code": string(loose), "public_key": pub(t), "device_name": "Laptop"})
	if res.StatusCode != 201 {
		t.Fatalf("client activate: %d %v", res.StatusCode, body)
	}
	token, _ := body["device_token"].(string)
	cfg := body["config"].(map[string]any)
	if cfg["address"] != "10.20.0.18/32" || cfg["endpoint"] != "165.227.89.92:51820" {
		t.Fatalf("config %v", cfg)
	}
	for k := range cfg {
		if k == "private_key" || k == "device_token" {
			t.Fatal("config must not carry secrets")
		}
	}
	// Re-using the code fails with a stable code.
	res, body = post(t, srv.URL+"/api/v1/activate", "", map[string]any{"code": clCode, "public_key": pub(t)})
	if res.StatusCode != 409 || body["code"] != "code_used" {
		t.Fatalf("reuse: %d %v", res.StatusCode, body)
	}
	// Config with the token works; without or with a bad token it does not.
	if res, _ := get(t, srv.URL+"/api/v1/device/config", token); res.StatusCode != 200 {
		t.Fatalf("config: %d", res.StatusCode)
	}
	if res, _ := get(t, srv.URL+"/api/v1/device/config", ""); res.StatusCode != 401 {
		t.Fatalf("no token: %d", res.StatusCode)
	}
	if res, _ := get(t, srv.URL+"/api/v1/device/config", "dnd_nope"); res.StatusCode != 401 {
		t.Fatalf("bad token: %d", res.StatusCode)
	}
	// Heartbeat reports the config version.
	res, body = post(t, srv.URL+"/api/v1/device/heartbeat", token, map[string]any{"client_version": "0.1", "connected": true})
	if res.StatusCode != 200 || body["ok"] != true {
		t.Fatalf("heartbeat: %d %v", res.StatusCode, body)
	}
	// Unknown JSON fields are rejected (no silent acceptance of e.g. "private_key").
	res, _ = post(t, srv.URL+"/api/v1/device/heartbeat", token, map[string]any{"client_version": "0.1", "private_key": "x"})
	if res.StatusCode != 400 {
		t.Fatalf("unknown field accepted: %d", res.StatusCode)
	}
	// Revoke: config and heartbeat now return 403 with reason.
	var devID int64
	_ = svc.DB().View(ctx, func(tx *store.Tx) error {
		ds, _ := tx.ListDevices(c.ID)
		for _, d := range ds {
			if d.Role == store.RoleClient {
				devID = d.ID
			}
		}
		return nil
	})
	if err := svc.RevokeDevice(ctx, devID, "test", "admin"); err != nil {
		t.Fatal(err)
	}
	res, body = get(t, srv.URL+"/api/v1/device/config", token)
	if res.StatusCode != 403 || body["reason"] != "revoked" {
		t.Fatalf("revoked config: %d %v", res.StatusCode, body)
	}
}

func TestActivationRateLimit(t *testing.T) {
	srv, _, _ := setup(t)
	var last int
	for i := 0; i < 6; i++ {
		res, _ := post(t, srv.URL+"/api/v1/activate", "", map[string]any{"code": "DN-AAAA-AAAA-AAAA-AAAA", "public_key": pub(t)})
		last = res.StatusCode
	}
	if last != 429 {
		t.Fatalf("6th attempt should be rate limited, got %d", last)
	}
}

func TestActivateRejectsBadInput(t *testing.T) {
	srv, svc, c := setup(t)
	code, _, _ := svc.CreateCode(context.Background(), provision.NewCode{CustomerID: c.ID, Role: store.RoleClient})
	cases := []struct {
		name string
		body any
		want int
		code string
	}{
		{"bad key", map[string]any{"code": code, "public_key": "zzz"}, 400, "bad_public_key"},
		{"unknown code", map[string]any{"code": "DN-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "public_key": pub(t)}, 401, "invalid_code"},
		{"bad lan", map[string]any{"code": code, "public_key": pub(t), "lan_subnets": []string{"nope"}}, 400, "bad_lan"},
		{"client with lan", map[string]any{"code": code, "public_key": pub(t), "lan_subnets": []string{"192.168.5.0/24"}}, 400, "lan_not_allowed"},
	}
	for _, tc := range cases {
		res, body := post(t, srv.URL+"/api/v1/activate", "", tc.body)
		if res.StatusCode != tc.want || body["code"] != tc.code {
			t.Fatalf("%s: got %d %v, want %d %s", tc.name, res.StatusCode, body, tc.want, tc.code)
		}
	}
	// Non-JSON body.
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/activate", bytes.NewReader([]byte("code=x")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != 415 {
		t.Fatalf("form body: %d", res.StatusCode)
	}
}
