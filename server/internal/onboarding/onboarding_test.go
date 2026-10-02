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
	if p.Done != 2 || !strings.Contains(p.NextAction, "Windows edition") || p.NextOwner != "DishNet support" {
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
	if !strings.Contains(p.NextAction, "readiness") {
		t.Fatalf("next should be readiness check, got %q", p.NextAction)
	}
	// Windows Home is flagged as attention with the recommended fix.
	in.Onboarding.OfficeEdition = "home"
	p = Compute(in)
	if !strings.Contains(p.NextAction, "Windows Home") || !strings.Contains(p.NextAction, "Windows Pro") {
		t.Fatalf("home: %q", p.NextAction)
	}
	// Everything entered: complete.
	in.Onboarding = store.Onboarding{OfficeEdition: "pro", Readiness: "ready", AcceptanceAt: now, AcceptanceBy: "bhavin", HandoverAt: now, HandoverBy: "bhavin"}
	p = Compute(in)
	if p.Done != p.Total || !strings.HasPrefix(p.NextAction, "Onboarding complete") {
		t.Fatalf("complete: %d/%d %q", p.Done, p.Total, p.NextAction)
	}
}
