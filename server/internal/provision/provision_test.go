package provision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

type harness struct {
	t      *testing.T
	svc    *Service
	wg     *wg.Fake
	fw     *firewall.Fake
	router *FakeRouter
	ctx    context.Context
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &harness{t: t, wg: wg.NewFake(), fw: &firewall.Fake{}, router: &FakeRouter{}, ctx: context.Background(), now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	h.svc = New(Config{Interface: "wg0", Endpoint: "165.227.89.92:51820", HubAddresses: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}, db, h.wg, h.fw, h.router,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	h.svc.SetClock(func() time.Time { return h.now })
	if err := h.svc.EnsurePool(h.ctx, "primary", netip.MustParsePrefix("10.20.0.0/24"), 28); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) customer(name string, ports ...int) store.Customer {
	h.t.Helper()
	c, err := h.svc.CreateCustomer(h.ctx, NewCustomer{Name: name, DeviceLimit: 5, DefaultPorts: ports, Actor: "test"})
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

func (h *harness) code(c store.Customer, role store.Role) string {
	h.t.Helper()
	code, _, err := h.svc.CreateCode(h.ctx, NewCode{CustomerID: c.ID, Role: role, Actor: "test"})
	if err != nil {
		h.t.Fatal(err)
	}
	return code
}

func newKey(t *testing.T) string {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func (h *harness) activate(code, name string, lans ...netip.Prefix) ActivateResult {
	h.t.Helper()
	res, err := h.svc.Activate(h.ctx, ActivateRequest{Code: code, PublicKey: newKey(h.t), DeviceName: name, LANSubnets: lans})
	if err != nil {
		h.t.Fatalf("activate %s: %v", name, err)
	}
	return res
}

func (h *harness) hasPeer(key string) bool {
	_, ok := h.wg.Peers[key]
	return ok
}

// ---------- activation ----------

func TestActivationProvisionsPeerAndReturnsConfig(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Kampala Traders", 3389, 9000)
	gw := h.activate(h.code(c, store.RoleGateway), "Office server")
	cl := h.activate(h.code(c, store.RoleClient), "Laptop")

	if gw.Config.Address != "10.20.0.17/32" || cl.Config.Address != "10.20.0.18/32" {
		t.Fatalf("unexpected addresses gw=%s cl=%s", gw.Config.Address, cl.Config.Address)
	}
	if !h.hasPeer(gw.Device.PublicKey) || !h.hasPeer(cl.Device.PublicKey) {
		t.Fatal("peers not on hub")
	}
	// Gateway routes the whole customer block back through the tunnel.
	if len(gw.Config.AllowedIPs) != 1 || gw.Config.AllowedIPs[0] != "10.20.0.16/28" {
		t.Fatalf("gateway allowed ips %v", gw.Config.AllowedIPs)
	}
	// Client only sees the hub (ping only) and the gateway: split tunnel, nothing else.
	if len(cl.Config.AllowedIPs) != 2 || cl.Config.AllowedIPs[0] != "10.20.0.1/32" || cl.Config.AllowedIPs[1] != "10.20.0.17/32" {
		t.Fatalf("client allowed ips %v", cl.Config.AllowedIPs)
	}
	if len(cl.Config.Access) != 1 || cl.Config.Access[0].Target != "10.20.0.17" || len(cl.Config.Access[0].Ports) != 2 {
		t.Fatalf("client access list %+v", cl.Config.Access)
	}
	if cl.Config.HubPublicKey != h.wg.Key || cl.Config.Endpoint != "165.227.89.92:51820" || cl.Config.Keepalive != 25 {
		t.Fatalf("hub parameters wrong: %+v", cl.Config)
	}
	if !strings.HasPrefix(cl.Token, "dnd_") {
		t.Fatal("device token missing")
	}
	// Hub-side allowed IPs are exact /32s — no spoofing another address.
	if p := h.wg.Peers[cl.Device.PublicKey]; len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "10.20.0.18/32" {
		t.Fatalf("hub allowed ips for client %v", p.AllowedIPs)
	}
	// Firewall carries exactly one rule: client -> gateway on the two ports.
	fw := h.fw.Last()
	if !strings.Contains(fw, "ip saddr 10.20.0.18 ip daddr 10.20.0.17 tcp dport { 3389, 9000 } accept") {
		t.Fatalf("expected client->gateway rule in:\n%s", fw)
	}
	if strings.Contains(fw, "ip saddr 10.20.0.17 ") {
		t.Fatal("gateway must not be able to initiate connections to clients")
	}
}

func TestActivationCodeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Single Use Ltd")
	code := h.code(c, store.RoleClient)
	h.activate(code, "first")
	_, err := h.svc.Activate(h.ctx, ActivateRequest{Code: code, PublicKey: newKey(t)})
	if !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("second use should fail with ErrCodeUsed, got %v", err)
	}
}

func TestUnauthorisedActivationIsRejected(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Rejects Ltd")
	cases := map[string]ActivateRequest{
		"garbage code":            {Code: "hello", PublicKey: newKey(t)},
		"well-formed but unknown": {Code: "DN-AAAA-BBBB-CCCC-DDDD", PublicKey: newKey(t)},
		"bad public key":          {Code: h.code(c, store.RoleClient), PublicKey: "not-a-key"},
	}
	for name, req := range cases {
		if _, err := h.svc.Activate(h.ctx, req); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
	if len(h.wg.Peers) != 0 {
		t.Fatal("no peer may be provisioned by a rejected activation")
	}
	// Revoked and expired codes.
	code, rec, _ := h.svc.CreateCode(h.ctx, NewCode{CustomerID: c.ID, Role: store.RoleClient})
	_ = h.svc.RevokeCode(h.ctx, rec.ID, "test")
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: code, PublicKey: newKey(t)}); !errors.Is(err, ErrCodeRevoked) {
		t.Fatalf("revoked code: got %v", err)
	}
	code2, _, _ := h.svc.CreateCode(h.ctx, NewCode{CustomerID: c.ID, Role: store.RoleClient, ExpiresAt: h.now.Add(time.Hour)})
	h.now = h.now.Add(2 * time.Hour)
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: code2, PublicKey: newKey(t)}); !errors.Is(err, ErrCodeExpired) {
		t.Fatalf("expired code: got %v", err)
	}
	// Device limit.
	small, _ := h.svc.CreateCustomer(h.ctx, NewCustomer{Name: "Tiny", DeviceLimit: 1})
	h.activate(h.code(small, store.RoleClient), "only")
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(small, store.RoleClient), PublicKey: newKey(t)}); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("device limit: got %v", err)
	}
	// Same public key twice.
	key := newKey(t)
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(c, store.RoleClient), PublicKey: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(c, store.RoleClient), PublicKey: key}); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate key: got %v", err)
	}
}

func TestConcurrentActivationsGetUniqueAddresses(t *testing.T) {
	h := newHarness(t)
	c, _ := h.svc.CreateCustomer(h.ctx, NewCustomer{Name: "Busy", DeviceLimit: 14})
	code, _, _ := h.svc.CreateCode(h.ctx, NewCode{CustomerID: c.ID, Role: store.RoleClient, MaxUses: 14})
	var wg sync.WaitGroup
	results := make(chan string, 40)
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.svc.Activate(h.ctx, ActivateRequest{Code: code, PublicKey: newKey(t), DeviceName: "x"})
			if err != nil {
				errs <- err
				return
			}
			results <- res.Config.Address
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	seen := map[string]bool{}
	for a := range results {
		if seen[a] {
			t.Fatalf("address %s allocated twice", a)
		}
		seen[a] = true
	}
	if len(seen) != 14 {
		t.Fatalf("expected exactly 14 successes (block capacity / max_uses), got %d", len(seen))
	}
	for err := range errs {
		if !errors.Is(err, ErrCodeUsed) && !errors.Is(err, ErrDeviceLimit) {
			t.Fatalf("unexpected error under concurrency: %v", err)
		}
	}
	if len(h.wg.Peers) != 14 {
		t.Fatalf("hub has %d peers, want 14", len(h.wg.Peers))
	}
}

// ---------- isolation ----------

func TestCustomersCannotReachEachOther(t *testing.T) {
	h := newHarness(t)
	a := h.customer("Customer A", 3389)
	b := h.customer("Customer B", 3389)
	aGW := h.activate(h.code(a, store.RoleGateway), "A server")
	aCL := h.activate(h.code(a, store.RoleClient), "A laptop")
	bGW := h.activate(h.code(b, store.RoleGateway), "B server")
	bCL := h.activate(h.code(b, store.RoleClient), "B laptop")

	fw := h.fw.Last()
	// Every rule mentions only same-customer addresses.
	for _, line := range strings.Split(fw, "\n") {
		if !strings.Contains(line, "accept comment") {
			continue
		}
		var src, dst string
		fmt.Sscanf(strings.TrimSpace(line), "ip saddr %s ip daddr %s", &src, &dst)
		sameA := strings.HasPrefix(src, "10.20.0.1") && strings.HasPrefix(dst, "10.20.0.1") // block 16/28: .17-.30
		sameB := strings.HasPrefix(src, "10.20.0.3") && strings.HasPrefix(dst, "10.20.0.3") // block 32/28: .33-.46
		if !(sameA || sameB) {
			t.Fatalf("cross-tenant rule generated: %s", line)
		}
	}
	mustHave := fmt.Sprintf("ip saddr %s ip daddr %s tcp dport { 3389 } accept", aCL.Device.VPNIP, aGW.Device.VPNIP)
	mustNot := fmt.Sprintf("ip saddr %s ip daddr %s", aCL.Device.VPNIP, bGW.Device.VPNIP)
	if !strings.Contains(fw, mustHave) {
		t.Fatalf("missing intra-tenant rule %q", mustHave)
	}
	if strings.Contains(fw, mustNot) {
		t.Fatalf("cross-tenant rule present %q", mustNot)
	}
	if !strings.Contains(fw, "policy accept") || !strings.Contains(fw, `counter drop comment "dishnet default deny"`) {
		t.Fatal("default deny missing")
	}
	// Client configs never list another customer's addresses.
	for _, ip := range bCL.Config.AllowedIPs {
		if ip != "10.20.0.1/32" && strings.HasPrefix(ip, "10.20.0.1") { // A's block is .17–.30; the hub .1 is allowed
			t.Fatalf("B client config routes A's addresses: %v", bCL.Config.AllowedIPs)
		}
	}
	if len(aCL.Config.AllowedIPs) != 2 || aCL.Config.AllowedIPs[1] != aGW.Config.Address {
		t.Fatalf("A client should route only the hub and A gateway, got %v", aCL.Config.AllowedIPs)
	}
	// An admin cannot create a policy pointing at another tenant's gateway.
	_, err := h.svc.CreatePolicy(h.ctx, NewPolicy{CustomerID: a.ID, ToDeviceID: bGW.Device.ID, Proto: store.ProtoTCP, Ports: []int{3389}})
	if !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant policy must be refused, got %v", err)
	}
	// Even a hand-inserted cross-tenant policy row is ignored by the generator.
	_ = h.svc.DB().Tx(h.ctx, func(tx *store.Tx) error {
		_, err := tx.InsertPolicy(store.AccessPolicy{CustomerID: a.ID, ToDeviceID: bGW.Device.ID, Proto: store.ProtoTCP, Ports: []int{3389}, Enabled: true})
		return err
	})
	_ = h.svc.Apply(h.ctx, "test")
	if strings.Contains(h.fw.Last(), mustNot) {
		t.Fatal("generator honoured a cross-tenant policy row")
	}
}

func TestSMBIsRefusedByDefault(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.CreateCustomer(h.ctx, NewCustomer{Name: "Shares", DefaultPorts: []int{445}}); err == nil {
		t.Fatal("SMB must be refused as a default port")
	}
	c := h.customer("Shares", 3389)
	gw := h.activate(h.code(c, store.RoleGateway), "srv")
	if _, err := h.svc.CreatePolicy(h.ctx, NewPolicy{CustomerID: c.ID, ToDeviceID: gw.Device.ID, Proto: store.ProtoTCP, Ports: []int{445}}); err == nil {
		t.Fatal("SMB policy must need the explicit override")
	}
	if _, err := h.svc.CreatePolicy(h.ctx, NewPolicy{CustomerID: c.ID, ToDeviceID: gw.Device.ID, Proto: store.ProtoTCP, Ports: []int{445}, AllowSMB: true}); err != nil {
		t.Fatalf("explicit override should work: %v", err)
	}
}

func TestModeBLANRoutingAndOverlap(t *testing.T) {
	h := newHarness(t)
	a := h.customer("A", 3389)
	b := h.customer("B", 3389)
	lan := netip.MustParsePrefix("192.168.10.0/24")
	aGW := h.activate(h.code(a, store.RoleGateway), "A router", lan)
	aCL := h.activate(h.code(a, store.RoleClient), "A laptop")
	// Hub routes the LAN via wg0 and the gateway's allowed IPs include it.
	if len(h.router.Routes) != 1 || h.router.Routes[0] != lan {
		t.Fatalf("routes %v", h.router.Routes)
	}
	if p := h.wg.Peers[aGW.Device.PublicKey]; len(p.AllowedIPs) != 2 {
		t.Fatalf("gateway allowed ips on hub %v", p.AllowedIPs)
	}
	// Another customer cannot declare an overlapping LAN.
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(b, store.RoleGateway), PublicKey: newKey(t), LANSubnets: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}); err == nil {
		t.Fatal("overlapping LAN must be refused")
	}
	// A LAN overlapping the VPN pool, or a public range, is refused.
	for _, bad := range []string{"10.20.0.0/24", "8.8.8.0/24"} {
		if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(b, store.RoleGateway), PublicKey: newKey(t), LANSubnets: []netip.Prefix{netip.MustParsePrefix(bad)}}); err == nil {
			t.Fatalf("LAN %s must be refused", bad)
		}
	}
	// A client may not declare LANs at all.
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(b, store.RoleClient), PublicKey: newKey(t), LANSubnets: []netip.Prefix{netip.MustParsePrefix("172.16.5.0/24")}}); !errors.Is(err, ErrLANNotAllowed) {
		t.Fatalf("client LAN: got %v", err)
	}
	// Policy to the LAN: client config gains the LAN route and the firewall the rule.
	if _, err := h.svc.CreatePolicy(h.ctx, NewPolicy{CustomerID: a.ID, ToDeviceID: aGW.Device.ID, ToCIDR: lan, Proto: store.ProtoTCP, Ports: []int{3389}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := h.svc.ConfigFor(h.ctx, aCL.Device.ID)
	if len(cfg.AllowedIPs) != 3 || cfg.AllowedIPs[2] != lan.String() {
		t.Fatalf("client allowed ips %v", cfg.AllowedIPs)
	}
	if !strings.Contains(h.fw.Last(), fmt.Sprintf("ip saddr %s ip daddr %s tcp dport { 3389 } accept", aCL.Device.VPNIP, lan)) {
		t.Fatalf("LAN rule missing:\n%s", h.fw.Last())
	}
}

// ---------- revocation, suspension, expiry ----------

func TestRevocationRemovesPeerAndDeniesConfig(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Rev", 3389)
	gw := h.activate(h.code(c, store.RoleGateway), "srv")
	cl := h.activate(h.code(c, store.RoleClient), "laptop")
	if err := h.svc.RevokeDevice(h.ctx, cl.Device.ID, "left company", "admin"); err != nil {
		t.Fatal(err)
	}
	if h.hasPeer(cl.Device.PublicKey) {
		t.Fatal("revoked peer still on hub")
	}
	if !h.hasPeer(gw.Device.PublicKey) {
		t.Fatal("unrelated peer removed")
	}
	if strings.Contains(h.fw.Last(), "ip saddr "+cl.Device.VPNIP.String()) {
		t.Fatal("firewall still allows revoked device")
	}
	_, err := h.svc.ConfigFor(h.ctx, cl.Device.ID)
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Reason != DeniedRevoked {
		t.Fatalf("config for revoked device: %v", err)
	}
	// The token still authenticates (so the client can learn it was revoked) but gets nothing.
	if _, err := h.svc.AuthenticateDevice(h.ctx, cl.Token); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.RotateKey(h.ctx, cl.Device.ID, newKey(t), ""); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("rotate on revoked: %v", err)
	}
	// The address is not reused by the next device.
	next := h.activate(h.code(c, store.RoleClient), "replacement")
	if next.Device.VPNIP == cl.Device.VPNIP {
		t.Fatal("revoked address must not be recycled")
	}
}

func TestSuspensionAndExpiryDropAllPeers(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Sub", 3389)
	other := h.customer("Other", 3389)
	gw := h.activate(h.code(c, store.RoleGateway), "srv")
	cl := h.activate(h.code(c, store.RoleClient), "laptop")
	oth := h.activate(h.code(other, store.RoleClient), "other laptop")

	if err := h.svc.SetCustomerStatus(h.ctx, c.ID, store.CustomerSuspended, "admin"); err != nil {
		t.Fatal(err)
	}
	if h.hasPeer(gw.Device.PublicKey) || h.hasPeer(cl.Device.PublicKey) {
		t.Fatal("suspended customer's peers still on hub")
	}
	if !h.hasPeer(oth.Device.PublicKey) {
		t.Fatal("other customer affected by suspension")
	}
	_, err := h.svc.ConfigFor(h.ctx, cl.Device.ID)
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Reason != DeniedSuspended {
		t.Fatalf("want suspended, got %v", err)
	}
	if _, err := h.svc.Activate(h.ctx, ActivateRequest{Code: h.code(c, store.RoleClient), PublicKey: newKey(t)}); !errors.Is(err, ErrCustomerBlocked) {
		t.Fatalf("activation for suspended customer: %v", err)
	}
	if err := h.svc.SetCustomerStatus(h.ctx, c.ID, store.CustomerActive, "admin"); err != nil {
		t.Fatal(err)
	}
	if !h.hasPeer(cl.Device.PublicKey) {
		t.Fatal("reactivation did not restore peers")
	}

	// Expiry: set a date, move the clock past it, reconcile (as the timer would).
	_ = h.svc.DB().Tx(h.ctx, func(tx *store.Tx) error {
		cc, _ := tx.GetCustomer(c.ID)
		cc.SubscriptionExpiresAt = h.now.Add(24 * time.Hour)
		return tx.UpdateCustomer(cc)
	})
	h.now = h.now.Add(48 * time.Hour)
	if err := h.svc.Reconcile(h.ctx); err != nil {
		t.Fatal(err)
	}
	if h.hasPeer(cl.Device.PublicKey) || h.hasPeer(gw.Device.PublicKey) {
		t.Fatal("expired customer's peers still on hub after reconcile")
	}
	if _, err := h.svc.ConfigFor(h.ctx, cl.Device.ID); !errors.As(err, &denied) || denied.Reason != DeniedExpired {
		t.Fatalf("want expired, got %v", err)
	}
	if !h.hasPeer(oth.Device.PublicKey) {
		t.Fatal("other customer affected by expiry")
	}
}

// ---------- recovery ----------

func TestRestartRecoveryRepopulatesEmptyHub(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Reboot", 3389)
	gw := h.activate(h.code(c, store.RoleGateway), "srv")
	cl := h.activate(h.code(c, store.RoleClient), "laptop")
	before := h.fw.Last()

	// Simulate wg-quick restart / reboot: kernel state gone, firewall gone.
	h.wg.Peers = map[string]wg.Peer{}
	h.fw.Applied = nil
	h.router.Routes = nil

	// A new service instance (fresh process) over the same database.
	svc2 := New(Config{Interface: "wg0", Endpoint: "165.227.89.92:51820", HubAddresses: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}, h.svc.DB(), h.wg, h.fw, h.router, nil)
	svc2.SetClock(func() time.Time { return h.now })
	if err := svc2.Reconcile(h.ctx); err != nil {
		t.Fatal(err)
	}
	if !h.hasPeer(gw.Device.PublicKey) || !h.hasPeer(cl.Device.PublicKey) {
		t.Fatal("peers not restored after restart")
	}
	if h.fw.Last() != before {
		t.Fatal("firewall after restart differs from before")
	}
}

func TestProvisioningFailureIsRecordedAndRecovered(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Flaky", 3389)
	h.wg.FailNext = errors.New("netlink: device busy")
	code := h.code(c, store.RoleClient)
	key := newKey(t)
	_, err := h.svc.Activate(h.ctx, ActivateRequest{Code: code, PublicKey: key, DeviceName: "laptop"})
	if !errors.Is(err, ErrProvisioning) {
		t.Fatalf("want ErrProvisioning, got %v", err)
	}
	var failed int
	_ = h.svc.DB().View(h.ctx, func(tx *store.Tx) error {
		failed, _ = tx.CountJobs(store.JobFailed)
		return nil
	})
	if failed != 1 {
		t.Fatalf("failed jobs = %d, want 1", failed)
	}
	// The device row exists (address kept) and the next reconcile provisions it.
	if err := h.svc.Reconcile(h.ctx); err != nil {
		t.Fatal(err)
	}
	if !h.hasPeer(key) {
		t.Fatal("reconcile did not recover the failed job")
	}
	_ = h.svc.DB().View(h.ctx, func(tx *store.Tx) error {
		failed, _ = tx.CountJobs(store.JobFailed)
		return nil
	})
	if failed != 0 {
		t.Fatalf("failed jobs after recovery = %d", failed)
	}
}

func TestStatsFlowIntoDevices(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Stats", 3389)
	cl := h.activate(h.code(c, store.RoleClient), "laptop")
	h.wg.SetStats(wg.Stats{PublicKey: cl.Device.PublicKey, LastHandshake: h.now, Endpoint: "41.210.1.2:51820", RxBytes: 1000, TxBytes: 2000})
	if err := h.svc.Reconcile(h.ctx); err != nil {
		t.Fatal(err)
	}
	_ = h.svc.DB().View(h.ctx, func(tx *store.Tx) error {
		d, _ := tx.GetDevice(cl.Device.ID)
		if d.RxBytes != 1000 || d.Endpoint != "41.210.1.2:51820" || d.LastHandshakeAt.IsZero() {
			t.Fatalf("stats not stored: %+v", d)
		}
		return nil
	})
}

func TestNoSecretsInConfigOrAudit(t *testing.T) {
	h := newHarness(t)
	c := h.customer("Secrets", 3389)
	code := h.code(c, store.RoleClient)
	res := h.activate(code, "laptop")
	blob := fmt.Sprintf("%+v", res.Config)
	if strings.Contains(blob, code) || strings.Contains(blob, res.Token) {
		t.Fatal("config leaks the activation code or device token")
	}
	_ = h.svc.DB().View(h.ctx, func(tx *store.Tx) error {
		entries, _ := tx.ListAudit(100)
		for _, e := range entries {
			if strings.Contains(e.Detail, code) || strings.Contains(e.Detail, res.Token) {
				t.Fatalf("audit log leaks a secret: %+v", e)
			}
		}
		return nil
	})
}
