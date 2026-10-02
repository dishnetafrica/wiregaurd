package desk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/wwt/guac"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

// fakeGuacd speaks just enough of the guacd protocol to complete a handshake
// and records what the hub asked for.
type fakeGuacd struct {
	ln       net.Listener
	mu       sync.Mutex
	connects [][]string // "connect" args per session, in the order of argNames
	sessions int
}

var argNames = []string{"VERSION_1_1_0", "hostname", "port", "username", "password", "domain", "security", "ignore-cert"}

func newFakeGuacd(t *testing.T) *fakeGuacd {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGuacd{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeGuacd) serve(c net.Conn) {
	defer c.Close()
	st := guac.NewStream(c, 5*time.Second)
	sel, err := guac.ReadOne(st)
	if err != nil || sel.Opcode != "select" || sel.Args[0] != "rdp" {
		return
	}
	_, _ = st.Write(guac.NewInstruction("args", argNames...).Byte())
	st.Flush()
	var connect *guac.Instruction
	for connect == nil {
		in, err := guac.ReadOne(st)
		if err != nil {
			return
		}
		if in.Opcode == "connect" {
			connect = in
		}
	}
	f.mu.Lock()
	f.sessions++
	f.connects = append(f.connects, connect.Args)
	f.mu.Unlock()
	_, _ = st.Write(guac.NewInstruction("ready", "$fake-session").Byte())
	st.Flush()
	// Keep the session alive until the client goes away.
	for {
		if _, err := guac.ReadOne(st); err != nil {
			return
		}
	}
}

func (f *fakeGuacd) last() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.connects) == 0 {
		return nil
	}
	m := map[string]string{}
	for i, n := range argNames {
		if i < len(f.connects[len(f.connects)-1]) {
			m[n] = f.connects[len(f.connects)-1][i]
		}
	}
	return m
}

type harness struct {
	t     *testing.T
	svc   *provision.Service
	srv   *httptest.Server
	guacd *fakeGuacd
}

func pubkey() string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	return base64.StdEncoding.EncodeToString(raw)
}

func setup(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "desk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := provision.New(provision.Config{Endpoint: "x:1", HubAddresses: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}, db, wg.NewFake(), &firewall.Fake{}, &provision.FakeRouter{}, log)
	_ = svc.EnsurePool(context.Background(), "primary", netip.MustParsePrefix("10.20.0.0/24"), 28)
	g := newFakeGuacd(t)
	h, err := New(svc, log, Options{SecureCookies: false, GuacdAddr: g.ln.Addr().String(), SupportContact: "WhatsApp 0705 993 348", DeskURL: "http://desk.test"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{t: t, svc: svc, srv: srv, guacd: g}
}

// customerWithOffice creates a customer whose office PC is registered (so the default RDP policy exists), with browser access on.
func (h *harness) customerWithOffice(name string) (store.Customer, provision.ActivateResult) {
	ctx := context.Background()
	c, err := h.svc.CreateCustomer(ctx, provision.NewCustomer{Name: name, DefaultPorts: []int{3389}})
	if err != nil {
		h.t.Fatal(err)
	}
	code, _, _ := h.svc.CreateCode(ctx, provision.NewCode{CustomerID: c.ID, Role: store.RoleGateway})
	gw, err := h.svc.Activate(ctx, provision.ActivateRequest{Code: code, PublicKey: pubkey(), DeviceName: "OFFICE-" + name, OS: "Windows 11 Pro"})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.svc.SetWebAccess(ctx, c.ID, true, "test"); err != nil {
		h.t.Fatal(err)
	}
	return c, gw
}

func (h *harness) user(c store.Customer, login string) (store.CustomerUser, string) {
	u, temp, err := h.svc.CreateCustomerUser(context.Background(), c.ID, login, "Test Person", "test")
	if err != nil {
		h.t.Fatal(err)
	}
	return u, temp
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var ticketRe = regexp.MustCompile(`data-ticket="([0-9a-f]+)"`)

func body(res *http.Response) string {
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return string(b)
}

// signIn performs first sign-in including the forced password change and returns the CSRF token.
func (h *harness) signIn(c *http.Client, login, temp, newPassword string) string {
	h.t.Helper()
	res, err := c.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {login}, "password": {temp}})
	if err != nil || res.StatusCode != 303 {
		h.t.Fatalf("login: %v %d", err, res.StatusCode)
	}
	res, _ = c.Get(h.srv.URL + "/desk/home")
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/desk/password") {
		h.t.Fatalf("temporary password must force a change: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = c.Get(h.srv.URL + "/desk/password?first=1")
	m := csrfRe.FindStringSubmatch(body(res))
	if m == nil {
		h.t.Fatal("no csrf on password page")
	}
	res, _ = c.PostForm(h.srv.URL+"/desk/password", url.Values{"csrf": {m[1]}, "current": {temp}, "new": {newPassword}, "again": {newPassword}})
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/desk/home") {
		h.t.Fatalf("password change: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	return m[1]
}

func (h *harness) openOffice(c *http.Client, csrf, winuser, winpass string) (string, *http.Response) {
	h.t.Helper()
	res, _ := c.PostForm(h.srv.URL+"/desk/office", url.Values{"csrf": {csrf}, "winuser": {winuser}, "winpass": {winpass}})
	b := body(res)
	m := ticketRe.FindStringSubmatch(b)
	if res.StatusCode != 200 || m == nil {
		h.t.Fatalf("office connect: %d %s", res.StatusCode, b[:min(len(b), 300)])
	}
	return m[1], res
}

func (h *harness) dialWS(c *http.Client, ticket string) (*websocket.Conn, *http.Response, error) {
	u, _ := url.Parse(h.srv.URL + "/desk/ws") // cookies are scoped to /desk
	hdr := http.Header{}
	for _, ck := range c.Jar.Cookies(u) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	d := websocket.Dialer{Subprotocols: []string{"guacamole"}, HandshakeTimeout: 5 * time.Second}
	return d.Dial("ws://"+u.Host+"/desk/ws?ticket="+ticket+"&width=1024&height=768&dpi=96", hdr)
}

func TestFullJourneyAndTenantIsolation(t *testing.T) {
	h := setup(t)
	a, gwA := h.customerWithOffice("Alpha Ltd")
	b, gwB := h.customerWithOffice("Beta Ltd")
	_, tempA := h.user(a, "amos.alpha")
	_, tempB := h.user(b, "grace.beta")

	// Grace (customer B) signs in, changes her password, sees only Beta's office computer.
	cb := client()
	csrf := h.signIn(cb, "grace.beta", tempB, "my-own-password-1")
	res, _ := cb.Get(h.srv.URL + "/desk/home")
	home := body(res)
	if !strings.Contains(home, "OFFICE-Beta Ltd") || strings.Contains(home, "OFFICE-Alpha Ltd") {
		t.Fatalf("home page leaks or lacks office: %s", home)
	}
	if strings.Contains(home, gwB.Device.VPNIP.String()) {
		t.Fatal("home page must not show VPN addresses")
	}
	// She types the office Windows account (PCNAME\user form) and gets a one-time ticket.
	ticket, _ := h.openOffice(cb, csrf, `OFFICE\grace`, "W1ndows-secret")
	ws, _, err := h.dialWS(cb, ticket)
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // let the handshake complete
	got := h.guacd.last()
	if got == nil || got["hostname"] != gwB.Device.VPNIP.String() || got["port"] != "3389" || got["username"] != "grace" || got["password"] != "W1ndows-secret" || got["domain"] != "OFFICE" {
		t.Fatalf("guacd got %v, want Beta's office %s", got, gwB.Device.VPNIP)
	}
	if got["hostname"] == gwA.Device.VPNIP.String() {
		t.Fatal("tenant isolation broken")
	}
	ws.Close()

	// The ticket is one-time: a second tunnel with it is refused and never reaches guacd.
	before := h.guacd.sessions
	ws2, _, err := h.dialWS(cb, ticket)
	if err == nil {
		ws2.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := ws2.ReadMessage(); err == nil {
			t.Fatal("reused ticket should not yield a session")
		}
		ws2.Close()
	}
	if h.guacd.sessions != before {
		t.Fatal("reused ticket reached guacd")
	}

	// Amos (customer A) cannot use Grace's ticket even if he obtained it.
	ca := client()
	csrfA := h.signIn(ca, "amos.alpha", tempA, "another-password-2")
	ticketB2, _ := h.openOffice(cb, csrf, "grace", "x")
	before = h.guacd.sessions
	if ws3, _, err := h.dialWS(ca, ticketB2); err == nil {
		ws3.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = ws3.ReadMessage()
		ws3.Close()
	}
	if h.guacd.sessions != before {
		t.Fatal("another customer's user redeemed the ticket")
	}
	// Amos's own session reaches Alpha's office only.
	ticketA, _ := h.openOffice(ca, csrfA, "amos", "pw")
	wsA, _, err := h.dialWS(ca, ticketA)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.guacd.last(); got["hostname"] != gwA.Device.VPNIP.String() {
		t.Fatalf("amos reached %s, want %s", got["hostname"], gwA.Device.VPNIP)
	}
	wsA.Close()

	// Audit never contains Windows credentials.
	_ = h.svc.DB().View(context.Background(), func(tx *store.Tx) error {
		entries, _ := tx.ListAudit(50)
		for _, e := range entries {
			if strings.Contains(e.Detail, "W1ndows-secret") || strings.Contains(e.Detail, "grace") && e.Action == "webdesk.connect" && strings.Contains(e.Detail, "OFFICE\\") {
				t.Fatalf("audit leaks credentials: %+v", e)
			}
		}
		return nil
	})
}

func TestAccessControls(t *testing.T) {
	h := setup(t)
	c, _ := h.customerWithOffice("Gamma Ltd")
	u, temp := h.user(c, "john.gamma")
	cl := client()
	// Wrong password.
	res, _ := cl.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {"john.gamma"}, "password": {"wrong"}})
	if res.StatusCode != 401 {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}
	// Unauthenticated pages redirect; websocket refused.
	if res, _ := cl.Get(h.srv.URL + "/desk/home"); res.StatusCode != 303 {
		t.Fatalf("anon home: %d", res.StatusCode)
	}
	if res, _ := cl.Get(h.srv.URL + "/desk/ws?ticket=abc"); res.StatusCode != 401 {
		t.Fatalf("anon ws: %d", res.StatusCode)
	}
	// Browser access off: sign-in refused with a clear message.
	_ = h.svc.SetWebAccess(context.Background(), c.ID, false, "test")
	res, _ = cl.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {"john.gamma"}, "password": {temp}})
	if res.StatusCode != 401 || !strings.Contains(body(res), "not enabled for your business") {
		t.Fatal("web access off must refuse sign-in")
	}
	_ = h.svc.SetWebAccess(context.Background(), c.ID, true, "test")
	// Disabled user.
	_ = h.svc.SetCustomerUserDisabled(context.Background(), u.ID, true, "test")
	res, _ = cl.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {"john.gamma"}, "password": {temp}})
	if res.StatusCode != 401 || !strings.Contains(body(res), "disabled") {
		t.Fatal("disabled user must be refused")
	}
	_ = h.svc.SetCustomerUserDisabled(context.Background(), u.ID, false, "test")
	// Rate limit: 10 attempts per 15 minutes per login.
	for i := 0; i < 12; i++ {
		res, _ = cl.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {"john.gamma"}, "password": {"wrong"}})
	}
	if res.StatusCode != 429 {
		t.Fatalf("rate limit: %d", res.StatusCode)
	}
}

func TestTwoFactor(t *testing.T) {
	h := setup(t)
	c, _ := h.customerWithOffice("Delta Ltd")
	u, temp := h.user(c, "mary.delta")
	cl := client()
	h.signIn(cl, "mary.delta", temp, "a-long-password-3")
	// Enrol through the page: the QR secret is shown, the current code enables it.
	res, _ := cl.Get(h.srv.URL + "/desk/security")
	page := body(res)
	m := regexp.MustCompile(`<span class="mono">([A-Z2-7]+)</span>`).FindStringSubmatch(page)
	csrf := csrfRe.FindStringSubmatch(page)
	if m == nil || csrf == nil {
		t.Fatalf("security page lacks secret or csrf")
	}
	if res, _ := cl.Get(h.srv.URL + "/desk/security/qr.png"); res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("qr: %d", res.StatusCode)
	}
	code, _ := auth.TOTPCode(m[1], time.Now())
	res, _ = cl.PostForm(h.srv.URL+"/desk/security/enable", url.Values{"csrf": {csrf[1]}, "code": {code}})
	if res.StatusCode != 303 || strings.Contains(res.Header.Get("Location"), "error") {
		t.Fatalf("enable: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// New sign-in now needs the code before anything else works.
	c2 := client()
	res, _ = c2.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {"mary.delta"}, "password": {"a-long-password-3"}})
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/desk/2fa") {
		t.Fatalf("login with 2fa: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := c2.Get(h.srv.URL + "/desk/home"); res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/desk/2fa") {
		t.Fatal("home must be blocked until the code is entered")
	}
	res, _ = c2.Get(h.srv.URL + "/desk/2fa")
	csrf2 := csrfRe.FindStringSubmatch(body(res))
	res, _ = c2.PostForm(h.srv.URL+"/desk/2fa", url.Values{"csrf": {csrf2[1]}, "code": {"000000"}})
	if res.StatusCode != 401 {
		t.Fatalf("bad code accepted: %d", res.StatusCode)
	}
	code, _ = auth.TOTPCode(m[1], time.Now())
	res, _ = c2.PostForm(h.srv.URL+"/desk/2fa", url.Values{"csrf": {csrf2[1]}, "code": {code}})
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/desk/home") {
		t.Fatalf("good code: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := c2.Get(h.srv.URL + "/desk/home"); res.StatusCode != 200 {
		t.Fatalf("home after 2fa: %d", res.StatusCode)
	}
	// Admin clears 2FA (lost phone): sessions dropped, next sign-in needs no code.
	_ = h.svc.ClearCustomerUserTOTP(context.Background(), u.ID, "admin")
	if res, _ := c2.Get(h.srv.URL + "/desk/home"); res.StatusCode != 303 {
		t.Fatal("clearing 2fa must sign the user out")
	}
	c3 := client()
	res, _ = c3.PostForm(h.srv.URL+"/desk/login", url.Values{"login": {"mary.delta"}, "password": {"a-long-password-3"}})
	if !strings.Contains(res.Header.Get("Location"), "/desk/home") {
		t.Fatalf("after clear: %s", res.Header.Get("Location"))
	}
	_ = fmt.Sprint
}
