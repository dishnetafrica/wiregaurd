package provision

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

// ---------- admin-entered onboarding facts ----------

type OnboardingUpdate struct {
	OfficeEdition string // unknown | pro | server | home
	Readiness     string // not_checked | ready | needs_attention
	ReadinessNote string
	MarkAccepted  bool
	MarkHandover  bool
}

func (s *Service) UpdateOnboarding(ctx context.Context, customerID int64, in OnboardingUpdate, actor string) error {
	switch in.OfficeEdition {
	case "unknown", "pro", "server", "home":
	default:
		return errors.New("invalid office edition")
	}
	switch in.Readiness {
	case "not_checked", "ready", "needs_attention":
	default:
		return errors.New("invalid readiness value")
	}
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.GetCustomer(customerID); err != nil {
			return err
		}
		o, err := tx.GetOnboarding(customerID)
		if err != nil {
			return err
		}
		o.OfficeEdition, o.Readiness, o.ReadinessNote = in.OfficeEdition, in.Readiness, clipStr(in.ReadinessNote, 300)
		if in.MarkAccepted && o.AcceptanceAt.IsZero() {
			o.AcceptanceAt, o.AcceptanceBy = s.now(), actor
		}
		if in.MarkHandover && o.HandoverAt.IsZero() {
			o.HandoverAt, o.HandoverBy = s.now(), actor
		}
		if err := tx.UpsertOnboarding(o); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "onboarding.update", Target: fmt.Sprintf("customer:%d", customerID), Detail: fmt.Sprintf("edition=%s readiness=%s accepted=%v handover=%v", o.OfficeEdition, o.Readiness, !o.AcceptanceAt.IsZero(), !o.HandoverAt.IsZero())})
	})
}

// AddSupportNote records a free-text note. Notes must never contain
// credentials; the UI says so and the server strips obvious ones.
func (s *Service) AddSupportNote(ctx context.Context, customerID int64, note, actor string) error {
	note = clipStr(note, 1000)
	if len(strings.TrimSpace(note)) < 2 {
		return errors.New("note is empty")
	}
	if strings.Contains(strings.ToLower(note), "password:") || strings.Contains(strings.ToLower(note), "passwd") {
		return errors.New("notes must not contain passwords")
	}
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.GetCustomer(customerID); err != nil {
			return err
		}
		if _, err := tx.InsertSupportNote(store.SupportNote{CustomerID: customerID, Author: actor, Note: note}); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "support.note", Target: fmt.Sprintf("customer:%d", customerID)})
	})
}

var _ = time.Now
