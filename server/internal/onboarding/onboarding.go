// Package onboarding derives a customer's setup progress for the dashboard.
// Every item says where its status comes from: observed by the system
// (telemetry) or entered by a person. The two are never mixed.
package onboarding

import (
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

type Source string

const (
	SourceSystem  Source = "verified" // handshakes, registrations, approvals recorded by the service
	SourceEntered Source = "entered"  // typed by an administrator or reported by the customer
)

type Status string

const (
	Done      Status = "done"
	Pending   Status = "pending"
	Attention Status = "attention"
)

type Item struct {
	Key, Title, Detail string
	Status             Status
	Source             Source
	Owner              string // who must act if not done
}

type Progress struct {
	Items      []Item
	Done       int
	Total      int
	NextAction string
	NextOwner  string
	Readiness  string // not_checked | ready | needs_attention (admin-entered)
}

// OnlineWindow mirrors the dashboard's definition of "online".
const OnlineWindow = 3 * time.Minute

type Input struct {
	Customer   store.Customer
	Devices    []store.Device
	Trial      *store.TrialRequest
	Onboarding store.Onboarding
	Policies   []store.AccessPolicy
	Now        time.Time
}

func Compute(in Input) Progress {
	var items []Item
	add := func(it Item) { items = append(items, it) }

	// 1. Customer record.
	add(Item{Key: "customer", Title: "Customer created", Detail: in.Customer.Name + " · " + string(in.Customer.Plan) + " plan", Status: Done, Source: SourceSystem, Owner: "DishNet admin"})

	// 2. Trial / approval.
	switch {
	case in.Trial != nil && in.Trial.Status == store.TrialApproved:
		add(Item{Key: "trial", Title: "Trial request approved", Detail: "Requested by " + in.Trial.ContactName + " (" + in.Trial.Phone + ")", Status: Done, Source: SourceSystem, Owner: "DishNet admin"})
	default:
		add(Item{Key: "trial", Title: "Customer created by DishNet", Detail: "No self-service request; created in the dashboard.", Status: Done, Source: SourceSystem, Owner: "DishNet admin"})
	}

	// 3. Office edition (entered).
	switch in.Onboarding.OfficeEdition {
	case "pro", "server":
		add(Item{Key: "edition", Title: "Office computer runs Windows Pro/Server", Detail: "Entered: " + in.Onboarding.OfficeEdition, Status: Done, Source: SourceEntered, Owner: "Customer IT contact"})
	case "home":
		add(Item{Key: "edition", Title: "Office computer runs Windows Home", Detail: "Cannot accept Remote Desktop. Recommend upgrading that PC to Windows Pro, or using another office PC.", Status: Attention, Source: SourceEntered, Owner: "Customer IT contact"})
	default:
		add(Item{Key: "edition", Title: "Confirm the office computer's Windows edition", Detail: "Ask the customer: Settings → System → About. Home cannot host Remote Desktop.", Status: Pending, Source: SourceEntered, Owner: "DishNet support"})
	}

	// 4./5. Gateway registered and online (observed).
	var gw *store.Device
	var clients []store.Device
	for i := range in.Devices {
		d := in.Devices[i]
		if d.Status != store.DeviceActive {
			continue
		}
		if d.Role == store.RoleGateway && gw == nil {
			gw = &in.Devices[i]
		} else if d.Role == store.RoleClient {
			clients = append(clients, d)
		}
	}
	if gw == nil {
		add(Item{Key: "gateway", Title: "Office computer registered", Detail: "Send the office install link; install on the PC that runs Tally.", Status: Pending, Source: SourceSystem, Owner: "Customer IT contact"})
		add(Item{Key: "gateway_online", Title: "Office computer online", Detail: "Checked once registered.", Status: Pending, Source: SourceSystem, Owner: "Customer IT contact"})
	} else {
		add(Item{Key: "gateway", Title: "Office computer registered", Detail: gw.Name + " · " + gw.VPNIP.String(), Status: Done, Source: SourceSystem, Owner: "Customer IT contact"})
		online := !gw.LastHandshakeAt.IsZero() && in.Now.Sub(gw.LastHandshakeAt) < OnlineWindow
		switch {
		case online:
			add(Item{Key: "gateway_online", Title: "Office computer online", Detail: "Handshake " + in.Now.Sub(gw.LastHandshakeAt).Round(time.Second).String() + " ago", Status: Done, Source: SourceSystem, Owner: "Customer IT contact"})
		case gw.LastHandshakeAt.IsZero():
			add(Item{Key: "gateway_online", Title: "Office computer has never connected", Detail: "The app on the office PC has not connected yet. Check it shows Connected and \"Allow Remote Desktop\" was clicked.", Status: Attention, Source: SourceSystem, Owner: "Customer IT contact"})
		default:
			add(Item{Key: "gateway_online", Title: "Office computer offline", Detail: "Last seen " + in.Now.Sub(gw.LastHandshakeAt).Round(time.Minute).String() + " ago. Is it switched on and online?", Status: Attention, Source: SourceSystem, Owner: "Customer IT contact"})
		}
	}

	// 6. Access policy to the gateway (observed).
	policyOK := false
	for _, p := range in.Policies {
		if p.Enabled && gw != nil && p.ToDeviceID == gw.ID {
			policyOK = true
		}
	}
	if gw != nil && !policyOK {
		add(Item{Key: "policy", Title: "No access policy to the office computer", Detail: "Add a policy (Remote Desktop 3389) on the customer page.", Status: Attention, Source: SourceSystem, Owner: "DishNet admin"})
	} else if gw != nil {
		add(Item{Key: "policy", Title: "Staff access policy in place", Detail: "Clients may reach the office computer on the allowed ports.", Status: Done, Source: SourceSystem, Owner: "DishNet admin"})
	}

	// 7. Staff devices (observed).
	if len(clients) == 0 {
		add(Item{Key: "clients", Title: "Staff computers registered", Detail: "Send the staff install link.", Status: Pending, Source: SourceSystem, Owner: "Customer"})
	} else {
		online := 0
		for _, c := range clients {
			if !c.LastHandshakeAt.IsZero() && in.Now.Sub(c.LastHandshakeAt) < OnlineWindow {
				online++
			}
		}
		add(Item{Key: "clients", Title: "Staff computers registered", Detail: itoa(len(clients)) + " registered, " + itoa(online) + " online now", Status: Done, Source: SourceSystem, Owner: "Customer"})
	}

	// 8. Readiness + acceptance (entered).
	switch in.Onboarding.Readiness {
	case "ready":
		add(Item{Key: "readiness", Title: "Remote Desktop / Tally readiness: Ready", Detail: in.Onboarding.ReadinessNote, Status: Done, Source: SourceEntered, Owner: "DishNet support"})
	case "needs_attention":
		add(Item{Key: "readiness", Title: "Remote Desktop / Tally readiness: Needs attention", Detail: in.Onboarding.ReadinessNote, Status: Attention, Source: SourceEntered, Owner: "DishNet support"})
	default:
		add(Item{Key: "readiness", Title: "Remote Desktop / Tally readiness: Not checked", Detail: "Support verifies Remote Desktop sign-in and Tally with the customer, then records the result here.", Status: Pending, Source: SourceEntered, Owner: "DishNet support"})
	}
	if !in.Onboarding.AcceptanceAt.IsZero() {
		add(Item{Key: "acceptance", Title: "Acceptance test passed", Detail: "Recorded by " + in.Onboarding.AcceptanceBy + " on " + in.Onboarding.AcceptanceAt.Format("2006-01-02"), Status: Done, Source: SourceEntered, Owner: "DishNet support"})
	} else {
		add(Item{Key: "acceptance", Title: "Acceptance test with the customer", Detail: "Customer signs in over Remote Desktop and opens Tally while support watches.", Status: Pending, Source: SourceEntered, Owner: "DishNet support"})
	}
	if !in.Onboarding.HandoverAt.IsZero() {
		add(Item{Key: "handover", Title: "Handover done", Detail: "Manual and support contact given; recorded by " + in.Onboarding.HandoverBy, Status: Done, Source: SourceEntered, Owner: "DishNet support"})
	} else {
		add(Item{Key: "handover", Title: "Handover: manual + support contact", Detail: "Send /guide.pdf and the support contact; record it here.", Status: Pending, Source: SourceEntered, Owner: "DishNet support"})
	}

	p := Progress{Items: items, Total: len(items), Readiness: in.Onboarding.Readiness}
	for _, it := range items {
		if it.Status == Done {
			p.Done++
		}
	}
	for _, it := range items {
		if it.Status == Attention {
			p.NextAction, p.NextOwner = it.Title+" — "+it.Detail, it.Owner
			return p
		}
	}
	for _, it := range items {
		if it.Status == Pending {
			p.NextAction, p.NextOwner = it.Title+" — "+it.Detail, it.Owner
			return p
		}
	}
	p.NextAction, p.NextOwner = "Onboarding complete. Manage trial/renewal and devices as usual.", "DishNet admin"
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
