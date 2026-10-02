package onboarding

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

func TestProgressDerivation(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c := store.Customer{ID: 1, Name: "Kishan Bhai", Plan: store.PlanTrial}
	base := Input{Customer: c, Now: now, Onboarding: store.Onboarding{OfficeEdition: "unknown", Readiness: "not_checked"}}

	// Nothing registered: next action is to confirm the Windows edition (support), nothing claimed as done except the record.
	p := Compute(base)
	if p.Done != 3 || !strings.Contains(p.NextAction, "Windows edition") || p.NextOwner != "DishNet support" {
		t.Fatalf("fresh: done=%d next=%q owner=%q", p.Done, p.NextAction, p.NextOwner)
	}

	// Gateway registered but never handshaked: attention, owner is the customer's IT contact; handshake-less is never "online".
	gw := store.Device{ID: 2, CustomerID: 1, Name: "KISHAN", Role: store.RoleGateway, Status: store.DeviceActive, VPNIP: netip.MustParseAddr("10.20.0.65")}
	in := base
	in.Devices = []store.Device{gw}
	in.Onboarding.OfficeEdition = "pro"
	p = Compute(in)
	if !strings.Contains(p.NextAction, "never connected") || p.NextOwner != "Customer IT contact" {
		t.Fatalf("no handshake: next=%q owner=%q", p.NextAction, p.NextOwner)
	}
	// Online gateway + policy + client: readiness still "not checked" — a handshake never implies Tally works.
	gw.LastHandshakeAt = now.Add(-30 * time.Second)
	cl := store.Device{ID: 3, CustomerID: 1, Name: "Laptop", Role: store.RoleClient, Status: store.DeviceActive, VPNIP: netip.MustParseAddr("10.20.0.66"), LastHandshakeAt: now.Add(-10 * time.Minute)}
	in.Devices = []store.Device{gw, cl}
	in.Policies = []store.AccessPolicy{{CustomerID: 1, ToDeviceID: 2, Enabled: true, Proto: store.ProtoTCP, Ports: []int{3389}}}
	p = Compute(in)
	var readiness Item
	for _, it := range p.Items {
		if it.Key == "readiness" {
			readiness = it
		}
		if it.Key == "gateway_online" && it.Status != Done {
			t.Fatalf("gateway should be online: %+v", it)
		}
		if it.Key == "clients" && !strings.Contains(it.Detail, "1 registered, 0 online") {
			t.Fatalf("clients detail: %q", it.Detail)
		}
	}
	if readiness.Status != Pending || readiness.Source != SourceEntered {
		t.Fatalf("readiness must stay pending/entered: %+v", readiness)
	}
	if !strings.Contains(p.NextAction, "Tally company") {
		t.Fatalf("next should be the Tally company (then readiness), got %q", p.NextAction)
	}
	in.Onboarding.TallyCompany = "Kishan Bhai Ltd"
	if p = Compute(in); !strings.Contains(p.NextAction, "readiness") {
		t.Fatalf("next should be readiness check, got %q", p.NextAction)
	}
	// Windows Home is flagged as attention with the recommended fix.
	in.Onboarding.OfficeEdition = "home"
	p = Compute(in)
	if !strings.Contains(p.NextAction, "Windows Home") || !strings.Contains(p.NextAction, "Windows Pro") {
		t.Fatalf("home: %q", p.NextAction)
	}
	// Everything entered: complete.
	in.Onboarding = store.Onboarding{OfficeEdition: "pro", Readiness: "ready", AcceptanceAt: now, AcceptanceBy: "bhavin", HandoverAt: now, HandoverBy: "bhavin", TallyCompany: "Kishan Bhai Ltd", ConcurrentUsers: 1}
	p = Compute(in)
	if p.Done != p.Total || !strings.HasPrefix(p.NextAction, "Onboarding complete") {
		t.Fatalf("complete: %d/%d %q", p.Done, p.Total, p.NextAction)
	}
}

func TestEditionVerifiedFromOfficeApp(t *testing.T) {
	now := time.Now()
	c := store.Customer{ID: 1, Name: "X", Plan: store.PlanTrial}
	home := store.Device{ID: 2, CustomerID: 1, Name: "KISHAN", Role: store.RoleGateway, Status: store.DeviceActive, VPNIP: netip.MustParseAddr("10.20.0.65"), OS: "Windows 11 Home 10.0.22631 x64", LastHandshakeAt: now}
	p := Compute(Input{Customer: c, Devices: []store.Device{home}, Onboarding: store.Onboarding{OfficeEdition: "pro", Readiness: "not_checked"}, Now: now})
	var ed Item
	for _, it := range p.Items {
		if it.Key == "edition" {
			ed = it
		}
	}
	// The app's report (verified) beats the admin's entry: Home is flagged even though an admin typed "pro".
	if ed.Status != Attention || ed.Source != SourceSystem || !strings.Contains(ed.Detail, "Windows Pro") {
		t.Fatalf("home from app: %+v", ed)
	}
	pro := home
	pro.OS = "Windows 11 Pro 10.0.22631 x64"
	p = Compute(Input{Customer: c, Devices: []store.Device{pro}, Onboarding: store.Onboarding{OfficeEdition: "unknown", Readiness: "not_checked"}, Now: now})
	for _, it := range p.Items {
		if it.Key == "edition" && (it.Status != Done || it.Source != SourceSystem) {
			t.Fatalf("pro from app: %+v", it)
		}
	}
}

func TestTallyPilotChecklistAndConcurrentAssessment(t *testing.T) {
	now := time.Now()
	c := store.Customer{ID: 1, Name: "X", Plan: store.PlanTrial}
	ob := store.Onboarding{OfficeEdition: "pro", Readiness: "ready", ConcurrentUsers: 3, ConcurrentAssessment: "needed", PilotChecks: []string{"understands", "vpn_reachable"}}
	p := Compute(Input{Customer: c, Onboarding: ob, Now: now})
	items := map[string]Item{}
	for _, it := range p.Items {
		items[it.Key] = it
	}
	if items["concurrent"].Status != Attention || !strings.Contains(items["concurrent"].Detail, "Windows Server") {
		t.Fatalf("3 concurrent users without assessment must be attention: %+v", items["concurrent"])
	}
	if items["acceptance"].Status != Pending || !strings.Contains(items["acceptance"].Title, "2 of 8") {
		t.Fatalf("partial checklist: %+v", items["acceptance"])
	}
	if items["tally_company"].Status != Pending {
		t.Fatalf("company missing should be pending: %+v", items["tally_company"])
	}
	// All eight ticked but acceptance not recorded: still pending, asks to record.
	ob.PilotChecks = nil
	for _, pc := range PilotChecks {
		ob.PilotChecks = append(ob.PilotChecks, pc.Key)
	}
	ob.ConcurrentAssessment, ob.TallyCompany = "assessed", "Kampala Traders Ltd"
	p = Compute(Input{Customer: c, Onboarding: ob, Now: now})
	for _, it := range p.Items {
		switch it.Key {
		case "acceptance":
			if it.Status != Done && !strings.Contains(it.Title, "record acceptance") {
				t.Fatalf("8/8 unrecorded: %+v", it)
			}
		case "concurrent":
			if it.Status != Done {
				t.Fatalf("assessed must be done: %+v", it)
			}
		case "tally_company":
			if it.Status != Done || !strings.Contains(it.Detail, "Kampala Traders Ltd") {
				t.Fatalf("company: %+v", it)
			}
		}
	}
	if !AllChecksPassed(ob.PilotChecks) || AllChecksPassed([]string{"task"}) {
		t.Fatal("AllChecksPassed wrong")
	}
}
