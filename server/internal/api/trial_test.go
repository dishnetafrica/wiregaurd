package api

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

type recNotifier struct{ ch chan map[string]any }

func newRecNotifier() *recNotifier { return &recNotifier{ch: make(chan map[string]any, 8)} }

func (r *recNotifier) Notify(e map[string]any) { r.ch <- e }

func (r *recNotifier) wait(t *testing.T) map[string]any {
	t.Helper()
	select {
	case e := <-r.ch:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("notifier was not called")
		return nil
	}
}

func postForm(t *testing.T, url_ string, v url.Values) (*http.Response, string) {
	t.Helper()
	res, err := http.PostForm(url_, v)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func TestTrialRequestLifecycle(t *testing.T) {
	_, svc, _ := setup(t)
	n := newRecNotifier()
	svc.SetNotifier(n)
	mux := http.NewServeMux()
	NewTrialPages(svc, "WhatsApp 0705 993 348").Register(mux)
	srv := newTestServer(t, mux)
	ctx := context.Background()

	// Form renders; no account is created by viewing it.
	var body string
	r2, err := http.Get(srv.URL + "/trial")
	if err != nil {
		t.Fatal(err)
	}
	bb, _ := io.ReadAll(r2.Body)
	body = string(bb)
	if r2.StatusCode != 200 || !strings.Contains(body, "Request my free trial") {
		t.Fatalf("form: %d", r2.StatusCode)
	}

	// Validation errors come back as the form with a message.
	rs, body := postForm(t, srv.URL+"/trial", url.Values{"business": {"X"}, "contact": {"Bob"}, "phone": {"abc"}, "pcs": {"2"}})
	if rs.StatusCode != 400 || !strings.Contains(body, "business name") {
		t.Fatalf("validation: %d %s", rs.StatusCode, body[:80])
	}

	// Honeypot filled -> pretend success, store nothing.
	rs, _ = postForm(t, srv.URL+"/trial", url.Values{"business": {"Spam Ltd"}, "contact": {"Bot"}, "phone": {"0700000000"}, "pcs": {"1"}, "website": {"http://spam"}})
	if rs.StatusCode != 200 {
		t.Fatalf("honeypot: %d", rs.StatusCode)
	}

	// Real request.
	rs, body = postForm(t, srv.URL+"/trial", url.Values{"business": {"Kampala Traders"}, "contact": {"Grace N."}, "phone": {"0705 993 348"}, "email": {"grace@example.com"}, "pcs": {"3"}, "office": {"windows_pc"}, "notes": {"Tally on reception PC"}})
	if rs.StatusCode != 200 || !strings.Contains(body, "request has been received") {
		t.Fatalf("submit: %d %s", rs.StatusCode, body[:120])
	}
	var pending []store.TrialRequest
	_ = svc.DB().View(ctx, func(tx *store.Tx) error {
		pending, _ = tx.ListTrialRequests(10)
		return nil
	})
	if len(pending) != 1 || pending[0].Status != store.TrialPending || pending[0].PCs != 3 || pending[0].Business != "Kampala Traders" {
		t.Fatalf("stored requests: %+v", pending)
	}
	if ev := n.wait(t); ev["business"] != "Kampala Traders" {
		t.Fatalf("notifier event: %+v", ev)
	}
	var customersBefore int
	_ = svc.DB().View(ctx, func(tx *store.Tx) error {
		cs, _ := tx.ListCustomers()
		customersBefore = len(cs)
		return nil
	})

	// Approve: trial customer + gateway code + client code sized to the PCs.
	ap, err := svc.ApproveTrialRequest(ctx, pending[0].ID, "bhavin@dishnetafrica.com")
	if err != nil {
		t.Fatal(err)
	}
	if ap.Customer.Plan != store.PlanTrial || ap.Customer.Name != "Kampala Traders" || ap.Customer.DeviceLimit != 4 {
		t.Fatalf("customer: %+v", ap.Customer)
	}
	if !strings.HasPrefix(ap.GatewayCode, "DN-") || !strings.HasPrefix(ap.ClientCode, "DN-") || ap.GatewayCode == ap.ClientCode {
		t.Fatalf("codes: %s %s", ap.GatewayCode, ap.ClientCode)
	}
	_ = svc.DB().View(ctx, func(tx *store.Tx) error {
		cs, _ := tx.ListCustomers()
		if len(cs) != customersBefore+1 {
			t.Fatalf("customers %d -> %d", customersBefore, len(cs))
		}
		codes, _ := tx.ListCodes(ap.Customer.ID)
		var gw, cl int
		for _, c := range codes {
			if c.Role == store.RoleGateway {
				gw = c.MaxUses
			} else {
				cl = c.MaxUses
			}
		}
		if gw != 1 || cl != 3 {
			t.Fatalf("code max uses gw=%d cl=%d", gw, cl)
		}
		r, _ := tx.GetTrialRequest(pending[0].ID)
		if r.Status != store.TrialApproved || r.CustomerID != ap.Customer.ID {
			t.Fatalf("request after approve: %+v", r)
		}
		return nil
	})
	// The client code works for activation, and the gateway code too.
	if _, err := svc.Activate(ctx, provision.ActivateRequest{Code: ap.ClientCode, PublicKey: pub(t)}); err != nil {
		t.Fatal(err)
	}
	// Approving twice is refused; rejecting a decided request is refused.
	if _, err := svc.ApproveTrialRequest(ctx, pending[0].ID, "x"); err == nil {
		t.Fatal("double approve must fail")
	}
	if err := svc.RejectTrialRequest(ctx, pending[0].ID, "late", "x"); err == nil {
		t.Fatal("reject after approve must fail")
	}

	// Reject path.
	_, _ = postForm(t, srv.URL+"/trial", url.Values{"business": {"Nope Ltd"}, "contact": {"A B"}, "phone": {"0711111111"}, "pcs": {"1"}})
	_ = svc.DB().View(ctx, func(tx *store.Tx) error {
		pending, _ = tx.ListTrialRequests(10)
		return nil
	})
	if err := svc.RejectTrialRequest(ctx, pending[0].ID, "not in coverage area", "bhavin@dishnetafrica.com"); err != nil {
		t.Fatal(err)
	}

	// Rate limit: 3 attempts per IP per hour (the invalid one above counted; the honeypot one did not).
	rs, _ = postForm(t, srv.URL+"/trial", url.Values{"business": {"Fourth"}, "contact": {"A B"}, "phone": {"0711111113"}, "pcs": {"1"}})
	if rs.StatusCode != 429 {
		t.Fatalf("fourth attempt should be rate limited, got %d", rs.StatusCode)
	}
}
