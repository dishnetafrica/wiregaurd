package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/policy"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

// ---------- public trial requests ----------

type TrialRequestInput struct {
	Business    string
	ContactName string
	Phone       string
	Email       string
	PCs         int
	OfficeType  string // windows_pc | windows_server | unknown
	Notes       string
	IP          string
}

var phoneRe = regexp.MustCompile(`^\+?[0-9][0-9 ()-]{6,19}$`)
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func clipStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SubmitTrialRequest validates and stores a request from the public form and
// fires the optional notifier. Nothing is provisioned until an admin approves.
func (s *Service) SubmitTrialRequest(ctx context.Context, in TrialRequestInput) (store.TrialRequest, error) {
	var out store.TrialRequest
	in.Business, in.ContactName, in.Email, in.Notes = clipStr(in.Business, 80), clipStr(in.ContactName, 80), strings.ToLower(clipStr(in.Email, 120)), clipStr(in.Notes, 500)
	in.Phone = strings.TrimSpace(in.Phone)
	switch {
	case len(in.Business) < 2:
		return out, errors.New("please enter your business name")
	case len(in.ContactName) < 2:
		return out, errors.New("please enter the contact person's name")
	case !phoneRe.MatchString(in.Phone):
		return out, errors.New("please enter a valid phone number (e.g. 0705 993 348)")
	case in.Email != "" && !emailRe.MatchString(in.Email):
		return out, errors.New("the email address does not look right")
	case in.PCs < 1 || in.PCs > 14:
		return out, errors.New("number of computers must be between 1 and 14")
	}
	switch in.OfficeType {
	case "windows_pc", "windows_server", "unknown":
	default:
		in.OfficeType = "unknown"
	}
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		var err error
		out, err = tx.InsertTrialRequest(store.TrialRequest{Business: in.Business, ContactName: in.ContactName, Phone: in.Phone, Email: in.Email, PCs: in.PCs, OfficeType: in.OfficeType, Notes: in.Notes, IP: in.IP})
		if err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "public", ActorID: "trial-form", Action: "trial.request", Target: fmt.Sprintf("trial:%d", out.ID), Detail: fmt.Sprintf("%s / %s / %d PCs", in.Business, in.ContactName, in.PCs), IP: in.IP})
	})
	if err == nil && s.notifier != nil {
		go s.notifier.Notify(map[string]any{"event": "trial.request", "id": out.ID, "business": out.Business, "contact": out.ContactName, "phone": out.Phone, "email": out.Email, "pcs": out.PCs, "office": out.OfficeType, "notes": out.Notes, "at": out.CreatedAt})
	}
	return out, err
}

// TrialApproval is what the admin sees once: the new customer and the codes/links.
type TrialApproval struct {
	Customer    store.Customer
	GatewayCode string
	ClientCode  string
}

// ApproveTrialRequest creates the 30-day trial customer with one gateway code
// and one multi-use client code sized to the requested number of PCs.
func (s *Service) ApproveTrialRequest(ctx context.Context, id int64, actor string) (TrialApproval, error) {
	var out TrialApproval
	var req store.TrialRequest
	if err := s.db.View(ctx, func(tx *store.Tx) error {
		var err error
		req, err = tx.GetTrialRequest(id)
		return err
	}); err != nil {
		return out, err
	}
	if req.Status != store.TrialPending {
		return out, errors.New("this request has already been decided")
	}
	contact := req.ContactName + " · " + req.Phone
	if req.Email != "" {
		contact += " · " + req.Email
	}
	c, err := s.CreateCustomer(ctx, NewCustomer{Name: req.Business, Contact: contact, DeviceLimit: req.PCs + 1, DefaultPorts: policy.Templates["rdp"], Plan: store.PlanTrial, Actor: actor})
	if err != nil {
		return out, err
	}
	gw, _, err := s.CreateCode(ctx, NewCode{CustomerID: c.ID, Role: store.RoleGateway, Label: "Office server (from trial request)", MaxUses: 1, ExpiresAt: s.now().Add(30 * 24 * time.Hour), Actor: actor})
	if err != nil {
		return out, err
	}
	cl, _, err := s.CreateCode(ctx, NewCode{CustomerID: c.ID, Role: store.RoleClient, Label: "Staff computers (from trial request)", MaxUses: req.PCs, ExpiresAt: s.now().Add(30 * 24 * time.Hour), Actor: actor})
	if err != nil {
		return out, err
	}
	if err := s.db.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.DecideTrialRequest(id, store.TrialApproved, c.ID, actor, ""); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "trial.approve", Target: fmt.Sprintf("trial:%d", id), Detail: fmt.Sprintf("customer=%d", c.ID)})
	}); err != nil {
		return out, err
	}
	return TrialApproval{Customer: c, GatewayCode: gw, ClientCode: cl}, nil
}

func (s *Service) RejectTrialRequest(ctx context.Context, id int64, note, actor string) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.DecideTrialRequest(id, store.TrialRejected, 0, actor, clipStr(note, 200)); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "trial.reject", Target: fmt.Sprintf("trial:%d", id), Detail: note})
	})
}

// ---------- notifications ----------

// Notifier receives events DishNet wants to hear about immediately (a new
// trial request). The webhook implementation posts JSON to any automation
// endpoint (Make/Zapier/n8n → WhatsApp or email).
type Notifier interface {
	Notify(event map[string]any)
}

func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

type WebhookNotifier struct {
	URL    string
	Client *http.Client
}

func (w *WebhookNotifier) Notify(event map[string]any) {
	body, _ := json.Marshal(event)
	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if res, err := c.Do(req); err == nil {
		res.Body.Close()
	}
}
