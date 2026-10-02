package provision

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/onboarding"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

// ---------- admin-entered onboarding facts ----------

type OnboardingUpdate struct {
	OfficeEdition string // unknown | pro | server | home
	Readiness     string // not_checked | ready | needs_attention
	ReadinessNote string
	MarkAccepted  bool
	MarkHandover  bool

	TallyCompany         string
	ConcurrentUsers      int
	ConcurrentAssessment string   // not_needed | needed | assessed
	PilotChecks          []string // keys from onboarding.PilotChecks
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
	if in.ConcurrentAssessment == "" {
		in.ConcurrentAssessment = "not_needed"
	}
	if in.ConcurrentUsers == 0 {
		in.ConcurrentUsers = 1
	}
	switch in.ConcurrentAssessment {
	case "not_needed", "needed", "assessed":
	default:
		return errors.New("invalid concurrent-users assessment value")
	}
	if in.ConcurrentUsers < 1 || in.ConcurrentUsers > 500 {
		return errors.New("concurrent users must be between 1 and 500")
	}
	var checks []string
	for _, k := range in.PilotChecks {
		known := false
		for _, c := range onboarding.PilotChecks {
			if c.Key == k {
				known = true
			}
		}
		if !known {
			return errors.New("unknown pilot check: " + k)
		}
		if !onboarding.HasCheck(checks, k) {
			checks = append(checks, k)
		}
	}
	if in.MarkAccepted && !onboarding.AllChecksPassed(checks) {
		return errors.New("acceptance can be recorded only when all 8 pilot checks are ticked")
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
		company := clipStr(in.TallyCompany, 80)
		if company != o.TallyCompany {
			if err := tx.BumpCustomerConfigVersion(customerID); err != nil { // staff apps refetch and show the new company name
				return err
			}
		}
		o.TallyCompany, o.ConcurrentUsers, o.ConcurrentAssessment, o.PilotChecks = company, in.ConcurrentUsers, in.ConcurrentAssessment, checks
		if in.MarkAccepted && o.AcceptanceAt.IsZero() {
			o.AcceptanceAt, o.AcceptanceBy = s.now(), actor
		}
		if in.MarkHandover && o.HandoverAt.IsZero() {
			o.HandoverAt, o.HandoverBy = s.now(), actor
		}
		if err := tx.UpsertOnboarding(o); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "onboarding.update", Target: fmt.Sprintf("customer:%d", customerID), Detail: fmt.Sprintf("edition=%s readiness=%s accepted=%v handover=%v checks=%d/%d concurrent=%d/%s", o.OfficeEdition, o.Readiness, !o.AcceptanceAt.IsZero(), !o.HandoverAt.IsZero(), len(o.PilotChecks), len(onboarding.PilotChecks), o.ConcurrentUsers, o.ConcurrentAssessment)})
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
