package store

import (
	"net/netip"
	"time"
)

type Pool struct {
	ID       int64
	Name     string
	CIDR     netip.Prefix
	BlockLen int
}

type CustomerStatus string

const (
	CustomerActive    CustomerStatus = "active"
	CustomerSuspended CustomerStatus = "suspended"
)

type Plan string

const (
	PlanTrial     Plan = "trial"     // time-limited evaluation; expires at SubscriptionExpiresAt
	PlanPaid      Plan = "paid"      // paid until SubscriptionExpiresAt
	PlanUnlimited Plan = "unlimited" // no expiry
)

func ParsePlan(s string) (Plan, bool) {
	switch Plan(s) {
	case PlanTrial, PlanPaid, PlanUnlimited:
		return Plan(s), true
	}
	return "", false
}

type Customer struct {
	ID                    int64
	Name                  string
	Contact               string
	Status                CustomerStatus
	Plan                  Plan
	SubscriptionExpiresAt time.Time // zero = never
	DeviceLimit           int
	DefaultPorts          []int // ports opened from clients to a newly registered gateway
	VPNBlock              netip.Prefix
	PoolID                int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// Expired reports whether the subscription has lapsed at time t.
func (c Customer) Expired(t time.Time) bool {
	return !c.SubscriptionExpiresAt.IsZero() && !t.Before(c.SubscriptionExpiresAt)
}

// Serviceable reports whether devices of this customer may be provisioned.
func (c Customer) Serviceable(t time.Time) bool {
	return c.Status == CustomerActive && !c.Expired(t)
}

type Role string

const (
	RoleClient  Role = "client"
	RoleGateway Role = "gateway"
)

func ParseRole(s string) (Role, bool) {
	switch Role(s) {
	case RoleClient, RoleGateway:
		return Role(s), true
	}
	return "", false
}

type ActivationCode struct {
	ID         int64
	CustomerID int64
	CodeHash   string
	CodeHint   string
	Role       Role
	Label      string
	MaxUses    int
	Uses       int
	ExpiresAt  time.Time
	RevokedAt  time.Time
	CreatedBy  string
	CreatedAt  time.Time
}

func (c ActivationCode) Usable(t time.Time) bool {
	if !c.RevokedAt.IsZero() || c.Uses >= c.MaxUses {
		return false
	}
	if !c.ExpiresAt.IsZero() && !t.Before(c.ExpiresAt) {
		return false
	}
	return true
}

type DeviceStatus string

const (
	DeviceActive  DeviceStatus = "active"
	DeviceRevoked DeviceStatus = "revoked"
)

type Device struct {
	ID              int64
	CustomerID      int64
	CodeID          int64
	Name            string
	Role            Role
	PublicKey       string
	VPNIP           netip.Addr
	LANSubnets      []netip.Prefix
	Status          DeviceStatus
	DeviceTokenHash string
	OS              string
	ClientVersion   string
	ConfigVersion   int
	LastSeenAt      time.Time
	LastHandshakeAt time.Time
	Endpoint        string
	RxBytes         int64
	TxBytes         int64
	RegisteredAt    time.Time
	RevokedAt       time.Time
	RevokedReason   string
}

type Proto string

const (
	ProtoTCP  Proto = "tcp"
	ProtoUDP  Proto = "udp"
	ProtoICMP Proto = "icmp"
)

type AccessPolicy struct {
	ID           int64
	CustomerID   int64
	FromDeviceID int64 // 0 = any client device of the customer
	ToDeviceID   int64
	ToCIDR       netip.Prefix // zero = the target device's own VPN address
	Proto        Proto
	Ports        []int
	Label        string
	Enabled      bool
	CreatedAt    time.Time
}

type JobAction string
type JobState string

const (
	JobAdd       JobAction = "add"
	JobRemove    JobAction = "remove"
	JobUpdate    JobAction = "update"
	JobReconcile JobAction = "reconcile"

	JobPending JobState = "pending"
	JobApplied JobState = "applied"
	JobFailed  JobState = "failed"
)

type Job struct {
	ID         int64
	CustomerID int64
	DeviceID   int64
	PublicKey  string
	Action     JobAction
	State      JobState
	Error      string
	Attempts   int
	CreatedAt  time.Time
	AppliedAt  time.Time
}

type AdminRole string

const (
	AdminOwner    AdminRole = "owner"
	AdminOperator AdminRole = "operator"
	AdminViewer   AdminRole = "viewer"
)

func ParseAdminRole(s string) (AdminRole, bool) {
	switch AdminRole(s) {
	case AdminOwner, AdminOperator, AdminViewer:
		return AdminRole(s), true
	}
	return "", false
}

type Admin struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         AdminRole
	Disabled     bool
	CreatedAt    time.Time
}

type AdminSession struct {
	TokenHash string
	AdminID   int64
	CSRFToken string
	ExpiresAt time.Time
}

type AuditEntry struct {
	ID        int64
	At        time.Time
	ActorType string
	ActorID   string
	Action    string
	Target    string
	Detail    string
	IP        string
}

type TrialStatus string

const (
	TrialPending  TrialStatus = "pending"
	TrialApproved TrialStatus = "approved"
	TrialRejected TrialStatus = "rejected"
)

type TrialRequest struct {
	ID           int64
	Business     string
	ContactName  string
	Phone        string
	Email        string
	PCs          int
	OfficeType   string
	Notes        string
	IP           string
	Status       TrialStatus
	CustomerID   int64
	DecidedBy    string
	DecisionNote string
	CreatedAt    time.Time
	DecidedAt    time.Time
}

type Onboarding struct {
	CustomerID    int64
	OfficeEdition string // unknown | pro | server | home  (entered by admin/customer, not observed)
	Readiness     string // not_checked | ready | needs_attention
	ReadinessNote string
	AcceptanceAt  time.Time
	AcceptanceBy  string
	HandoverAt    time.Time
	HandoverBy    string
	// Tally remote-access readiness (entered by DishNet staff).
	TallyCompany         string   // the Tally company the customer should open; shown in the staff app
	ConcurrentUsers      int      // how many staff need Tally at the same time (1 = standard Windows Pro)
	ConcurrentAssessment string   // not_needed | needed | assessed  (Windows Server / RDS licensing assessment)
	PilotChecks          []string // keys of the 8 pilot acceptance checks ticked so far
	UpdatedAt            time.Time
}

type SupportNote struct {
	ID         int64
	CustomerID int64
	Author     string
	Note       string
	CreatedAt  time.Time
}
