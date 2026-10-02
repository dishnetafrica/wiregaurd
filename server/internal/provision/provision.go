// Package provision is the heart of the backend: it owns every change to
// customers, codes and devices, and converges the hub (peers, firewall,
// routes) to what the database says. All hub changes go through Apply, which
// is idempotent, so a crash at any point is repaired by the next
// reconciliation.
package provision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/ipam"
	"github.com/dishnetafrica/wiregaurd/server/internal/policy"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

// Router installs kernel routes for office LANs (Mode B) via wg0.
type Router interface {
	EnsureRoutes(ctx context.Context, iface string, prefixes []netip.Prefix) error
}

// IPRoute shells out to the fixed binary /usr/sbin/ip with validated
// arguments only. Stale routes are not removed automatically (a reboot
// clears them, and a stale route to wg0 is harmless because the firewall
// and cryptokey routing still deny the traffic).
type IPRoute struct{ Binary string }

func (r IPRoute) EnsureRoutes(ctx context.Context, iface string, prefixes []netip.Prefix) error {
	bin := r.Binary
	if bin == "" {
		bin = "/usr/sbin/ip"
	}
	for _, p := range prefixes {
		p = p.Masked()
		if !p.Addr().Is4() {
			continue
		}
		out, err := exec.CommandContext(ctx, bin, "route", "replace", p.String(), "dev", iface).CombinedOutput()
		if err != nil {
			return fmt.Errorf("provision: ip route replace %s: %v: %s", p, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

type FakeRouter struct{ Routes []netip.Prefix }

func (f *FakeRouter) EnsureRoutes(ctx context.Context, iface string, p []netip.Prefix) error {
	f.Routes = p
	return nil
}

// Config of the service.
type Config struct {
	Interface    string
	Endpoint     string // host:port the clients dial
	HubAddresses []netip.Addr
	Keepalive    int
}

type Service struct {
	cfg      Config
	db       *store.DB
	wg       wg.Backend
	fw       firewall.Applier
	router   Router
	log      *slog.Logger
	applyMu  sync.Mutex
	now      func() time.Time
	hubKey   string
	hubKeyMu sync.Mutex
}

func New(cfg Config, db *store.DB, backend wg.Backend, fw firewall.Applier, router Router, log *slog.Logger) *Service {
	if cfg.Keepalive == 0 {
		cfg.Keepalive = 25
	}
	if cfg.Interface == "" {
		cfg.Interface = "wg0"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{cfg: cfg, db: db, wg: backend, fw: fw, router: router, log: log, now: time.Now}
}

// SetClock is for tests (expiry).
func (s *Service) SetClock(f func() time.Time) { s.now = f }

func (s *Service) DB() *store.DB { return s.db }

// ---------- errors surfaced to the API ----------

var (
	ErrInvalidCode      = errors.New("activation code is invalid")
	ErrCodeUsed         = errors.New("activation code has already been used")
	ErrCodeExpired      = errors.New("activation code has expired")
	ErrCodeRevoked      = errors.New("activation code was revoked")
	ErrCustomerBlocked  = errors.New("customer account is suspended or expired")
	ErrDeviceLimit      = errors.New("device limit reached for this customer")
	ErrBadPublicKey     = errors.New("public key is not a valid WireGuard key")
	ErrDeviceRevoked    = errors.New("device has been revoked")
	ErrProvisioning     = errors.New("provisioning failed; the administrator has been notified")
	ErrBlockFull        = errors.New("no free address in the customer's block")
	ErrLANNotAllowed    = errors.New("lan subnets may only be declared by gateway devices")
	ErrDuplicateKey     = errors.New("this public key is already registered")
	ErrNoPool           = errors.New("no address pool configured")
	ErrPoolFull         = errors.New("all address pools are full")
	ErrCrossTenant      = errors.New("policy references a device of another customer")
	ErrPolicyTargetRole = errors.New("policy target must be a gateway device")
)

// ---------- bootstrap ----------

// EnsurePool makes sure the given pool exists (idempotent). Called at start-up
// with the primary pool from configuration.
func (s *Service) EnsurePool(ctx context.Context, name string, cidr netip.Prefix, blockLen int) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		pools, err := tx.ListPools()
		if err != nil {
			return err
		}
		for _, p := range pools {
			if p.CIDR == cidr.Masked() {
				return nil
			}
			if ipam.Overlaps(p.CIDR, cidr) {
				return fmt.Errorf("pool %s overlaps existing pool %s", cidr, p.CIDR)
			}
		}
		_, err = tx.InsertPool(name, cidr, blockLen)
		return err
	})
}

// ---------- customers ----------

type NewCustomer struct {
	Name         string
	Contact      string
	DeviceLimit  int
	DefaultPorts []int
	ExpiresAt    time.Time
	Actor        string
}

func (s *Service) CreateCustomer(ctx context.Context, in NewCustomer) (store.Customer, error) {
	var out store.Customer
	if strings.TrimSpace(in.Name) == "" {
		return out, errors.New("customer name is required")
	}
	if in.DeviceLimit <= 0 {
		in.DeviceLimit = 5
	}
	if len(in.DefaultPorts) == 0 {
		in.DefaultPorts = policy.Templates["rdp"]
	}
	if err := policy.ValidatePorts(in.DefaultPorts, false); err != nil {
		return out, err
	}
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		pools, err := tx.ListPools()
		if err != nil {
			return err
		}
		if len(pools) == 0 {
			return ErrNoPool
		}
		var block netip.Prefix
		var poolID int64
		for _, p := range pools {
			used, err := tx.UsedBlocks(p.ID)
			if err != nil {
				return err
			}
			if in.DeviceLimit > ipam.Capacity(netip.PrefixFrom(p.CIDR.Addr(), p.BlockLen)) {
				return fmt.Errorf("device limit %d exceeds block capacity %d", in.DeviceLimit, ipam.Capacity(netip.PrefixFrom(p.CIDR.Addr(), p.BlockLen)))
			}
			b, err := ipam.NextFreeBlock(p.CIDR, p.BlockLen, used)
			if errors.Is(err, ipam.ErrPoolFull) {
				continue
			}
			if err != nil {
				return err
			}
			block, poolID = b, p.ID
			break
		}
		if !block.IsValid() {
			return ErrPoolFull
		}
		c, err := tx.InsertCustomer(store.Customer{
			Name: strings.TrimSpace(in.Name), Contact: strings.TrimSpace(in.Contact), DeviceLimit: in.DeviceLimit,
			DefaultPorts: in.DefaultPorts, SubscriptionExpiresAt: in.ExpiresAt, VPNBlock: block, PoolID: poolID,
		})
		if err != nil {
			return err
		}
		out = c
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: in.Actor, Action: "customer.create", Target: fmt.Sprintf("customer:%d", c.ID), Detail: fmt.Sprintf("%s block=%s", c.Name, block)})
	})
	return out, err
}

// SetCustomerStatus suspends or reactivates; the hub is converged immediately.
func (s *Service) SetCustomerStatus(ctx context.Context, id int64, status store.CustomerStatus, actor string) error {
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		c, err := tx.GetCustomer(id)
		if err != nil {
			return err
		}
		c.Status = status
		if err := tx.UpdateCustomer(c); err != nil {
			return err
		}
		if err := tx.BumpCustomerConfigVersion(id); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "customer." + string(status), Target: fmt.Sprintf("customer:%d", id)})
	})
	if err != nil {
		return err
	}
	return s.Apply(ctx, "customer status change")
}

func (s *Service) UpdateCustomer(ctx context.Context, c store.Customer, actor string) error {
	if err := policy.ValidatePorts(c.DefaultPorts, false); err != nil {
		return err
	}
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.UpdateCustomer(c); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "customer.update", Target: fmt.Sprintf("customer:%d", c.ID), Detail: fmt.Sprintf("expires=%s limit=%d", c.SubscriptionExpiresAt.Format(time.RFC3339), c.DeviceLimit)})
	})
	if err != nil {
		return err
	}
	return s.Apply(ctx, "customer update")
}

// ---------- activation codes ----------

type NewCode struct {
	CustomerID int64
	Role       store.Role
	Label      string
	MaxUses    int
	ExpiresAt  time.Time
	Actor      string
}

// CreateCode returns the plaintext code exactly once.
func (s *Service) CreateCode(ctx context.Context, in NewCode) (string, store.ActivationCode, error) {
	if in.MaxUses <= 0 {
		in.MaxUses = 1
	}
	if in.MaxUses > 50 {
		return "", store.ActivationCode{}, errors.New("max uses too large")
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = s.now().Add(14 * 24 * time.Hour)
	}
	code, hash, hint, err := auth.NewActivationCode()
	if err != nil {
		return "", store.ActivationCode{}, err
	}
	var rec store.ActivationCode
	err = s.db.Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.GetCustomer(in.CustomerID); err != nil {
			return err
		}
		rec, err = tx.InsertCode(store.ActivationCode{CustomerID: in.CustomerID, CodeHash: hash, CodeHint: hint, Role: in.Role, Label: in.Label, MaxUses: in.MaxUses, ExpiresAt: in.ExpiresAt, CreatedBy: in.Actor})
		if err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: in.Actor, Action: "code.create", Target: fmt.Sprintf("code:%d", rec.ID), Detail: fmt.Sprintf("customer=%d role=%s hint=%s", in.CustomerID, in.Role, hint)})
	})
	return code, rec, err
}

func (s *Service) RevokeCode(ctx context.Context, id int64, actor string) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.RevokeCode(id); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "code.revoke", Target: fmt.Sprintf("code:%d", id)})
	})
}

// ---------- activation ----------

type ActivateRequest struct {
	Code          string
	PublicKey     string
	DeviceName    string
	OS            string
	ClientVersion string
	LANSubnets    []netip.Prefix // gateway only
	RemoteIP      string
}

type ActivateResult struct {
	Device store.Device
	Token  string
	Config DeviceConfig
}

// Activate validates the code, allocates an address, records the device and
// provisions the hub. The database transaction commits before the hub is
// touched; if provisioning fails the device is left in the database with a
// failed job for the administrator and the client receives an error — the
// reconciler will provision it as soon as the hub accepts changes again, and
// the client's next /config call succeeds. This is deliberate: a crash
// between commit and apply must not lose an allocated address.
func (s *Service) Activate(ctx context.Context, in ActivateRequest) (ActivateResult, error) {
	var res ActivateResult
	code, err := auth.NormaliseCode(in.Code)
	if err != nil {
		return res, ErrInvalidCode
	}
	pubKey, err := wgtypes.ParseKey(strings.TrimSpace(in.PublicKey))
	if err != nil {
		return res, ErrBadPublicKey
	}
	name := strings.TrimSpace(in.DeviceName)
	if name == "" {
		name = "Windows device"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	token, tokenHash, err := auth.NewDeviceToken()
	if err != nil {
		return res, err
	}
	now := s.now()
	var job store.Job
	err = s.db.Tx(ctx, func(tx *store.Tx) error {
		ac, err := tx.GetCodeByHash(auth.HashCode(code))
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidCode
		}
		if err != nil {
			return err
		}
		switch {
		case !ac.RevokedAt.IsZero():
			return ErrCodeRevoked
		case !ac.ExpiresAt.IsZero() && !now.Before(ac.ExpiresAt):
			return ErrCodeExpired
		case ac.Uses >= ac.MaxUses:
			return ErrCodeUsed
		}
		c, err := tx.GetCustomer(ac.CustomerID)
		if err != nil {
			return err
		}
		if !c.Serviceable(now) {
			return ErrCustomerBlocked
		}
		n, err := tx.CountActiveDevices(c.ID)
		if err != nil {
			return err
		}
		if n >= c.DeviceLimit {
			return ErrDeviceLimit
		}
		if len(in.LANSubnets) > 0 {
			if ac.Role != store.RoleGateway {
				return ErrLANNotAllowed
			}
			pools, err := tx.ListPools()
			if err != nil {
				return err
			}
			others, err := tx.ListAllDevices()
			if err != nil {
				return err
			}
			for _, lan := range in.LANSubnets {
				if err := policy.ValidateLAN(lan, c.ID, pools, others); err != nil {
					return err
				}
			}
		}
		used, err := tx.UsedAddresses(c.ID)
		if err != nil {
			return err
		}
		ip, err := ipam.NextFreeHost(c.VPNBlock, used)
		if err != nil {
			return ErrBlockFull
		}
		ok, err := tx.ConsumeCode(ac.ID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrCodeUsed
		}
		d, err := tx.InsertDevice(store.Device{
			CustomerID: c.ID, CodeID: ac.ID, Name: name, Role: ac.Role, PublicKey: pubKey.String(), VPNIP: ip,
			LANSubnets: in.LANSubnets, DeviceTokenHash: tokenHash, OS: in.OS, ClientVersion: in.ClientVersion,
		})
		if errors.Is(err, store.ErrDuplicateKey) {
			return ErrDuplicateKey
		}
		if err != nil {
			return err
		}
		// A newly registered gateway automatically receives the customer's
		// default policy (any client -> gateway on the default ports).
		if d.Role == store.RoleGateway && len(c.DefaultPorts) > 0 {
			if _, err := tx.InsertPolicy(store.AccessPolicy{CustomerID: c.ID, ToDeviceID: d.ID, Proto: store.ProtoTCP, Ports: c.DefaultPorts, Label: "default " + d.Name, Enabled: true}); err != nil {
				return err
			}
			if err := tx.BumpCustomerConfigVersion(c.ID); err != nil {
				return err
			}
		}
		job, err = tx.InsertJob(store.Job{CustomerID: c.ID, DeviceID: d.ID, PublicKey: d.PublicKey, Action: store.JobAdd})
		if err != nil {
			return err
		}
		res.Device = d
		return tx.Audit(store.AuditEntry{ActorType: "device", ActorID: fmt.Sprintf("%d", d.ID), Action: "device.activate", Target: fmt.Sprintf("device:%d", d.ID), Detail: fmt.Sprintf("customer=%d role=%s ip=%s code=%d", c.ID, d.Role, ip, ac.ID), IP: in.RemoteIP})
	})
	if err != nil {
		return res, err
	}
	if err := s.applyJob(ctx, job); err != nil {
		s.log.Error("provisioning failed after activation", "device", res.Device.ID, "err", err)
		return res, ErrProvisioning
	}
	cfg, err := s.ConfigFor(ctx, res.Device.ID)
	if err != nil {
		return res, err
	}
	res.Token = token
	res.Config = cfg
	return res, nil
}

// ---------- device configuration ----------

type DeviceConfig struct {
	DeviceID      int64          `json:"device_id"`
	DeviceName    string         `json:"device_name"`
	Role          store.Role     `json:"role"`
	CustomerName  string         `json:"customer_name"`
	Address       string         `json:"address"` // "10.20.0.18/32"
	HubPublicKey  string         `json:"hub_public_key"`
	Endpoint      string         `json:"endpoint"`
	AllowedIPs    []string       `json:"allowed_ips"`
	Keepalive     int            `json:"persistent_keepalive"`
	DNS           []string       `json:"dns"`
	Access        []AccessTarget `json:"access"`
	ConfigVersion int            `json:"config_version"`
	ExpiresAt     string         `json:"subscription_expires_at,omitempty"`
}

type AccessTarget struct {
	Label  string `json:"label"`
	Target string `json:"target"`
	Proto  string `json:"proto"`
	Ports  []int  `json:"ports"`
}

var ErrAccessDenied = errors.New("access denied")

// DeniedReason distinguishes why a device no longer gets configuration.
type DeniedReason string

const (
	DeniedRevoked   DeniedReason = "revoked"
	DeniedSuspended DeniedReason = "suspended"
	DeniedExpired   DeniedReason = "expired"
)

type DeniedError struct{ Reason DeniedReason }

func (e *DeniedError) Error() string { return "access denied: " + string(e.Reason) }

func (s *Service) hubPublicKey(ctx context.Context) (string, error) {
	s.hubKeyMu.Lock()
	defer s.hubKeyMu.Unlock()
	if s.hubKey != "" {
		return s.hubKey, nil
	}
	k, err := s.wg.PublicKey(ctx)
	if err != nil {
		return "", err
	}
	s.hubKey = k
	return k, nil
}

// ConfigFor renders the configuration a device must apply. It never includes
// private material.
func (s *Service) ConfigFor(ctx context.Context, deviceID int64) (DeviceConfig, error) {
	var cfg DeviceConfig
	hubKey, err := s.hubPublicKey(ctx)
	if err != nil {
		return cfg, err
	}
	now := s.now()
	err = s.db.View(ctx, func(tx *store.Tx) error {
		d, err := tx.GetDevice(deviceID)
		if err != nil {
			return err
		}
		if d.Status != store.DeviceActive {
			return &DeniedError{DeniedRevoked}
		}
		c, err := tx.GetCustomer(d.CustomerID)
		if err != nil {
			return err
		}
		if c.Status == store.CustomerSuspended {
			return &DeniedError{DeniedSuspended}
		}
		if c.Expired(now) {
			return &DeniedError{DeniedExpired}
		}
		devices, err := tx.ListDevices(c.ID)
		if err != nil {
			return err
		}
		policies, err := tx.ListPolicies(c.ID)
		if err != nil {
			return err
		}
		allowed := policy.ClientAllowedIPs(d, c, devices, policies)
		cfg = DeviceConfig{
			DeviceID: d.ID, DeviceName: d.Name, Role: d.Role, CustomerName: c.Name,
			Address: netip.PrefixFrom(d.VPNIP, 32).String(), HubPublicKey: hubKey, Endpoint: s.cfg.Endpoint,
			Keepalive: s.cfg.Keepalive, DNS: []string{}, ConfigVersion: d.ConfigVersion, AllowedIPs: []string{},
		}
		// The hub's own address is always routed so a client can `ping
		// 10.20.0.1` as a connectivity check; the hub firewall allows only
		// ICMP echo to itself, nothing else.
		if d.Role == store.RoleClient {
			for _, h := range s.cfg.HubAddresses {
				allowed = append([]netip.Prefix{netip.PrefixFrom(h, 32)}, allowed...)
			}
		}
		for _, a := range allowed {
			cfg.AllowedIPs = append(cfg.AllowedIPs, a.String())
		}
		if !c.SubscriptionExpiresAt.IsZero() {
			cfg.ExpiresAt = c.SubscriptionExpiresAt.UTC().Format(time.RFC3339)
		}
		byID := map[int64]store.Device{}
		for _, x := range devices {
			byID[x.ID] = x
		}
		if d.Role == store.RoleClient {
			for _, p := range policies {
				if !p.Enabled || (p.FromDeviceID != 0 && p.FromDeviceID != d.ID) {
					continue
				}
				to, ok := byID[p.ToDeviceID]
				if !ok || to.Status != store.DeviceActive {
					continue
				}
				target := to.VPNIP.String()
				if p.ToCIDR.IsValid() {
					target = p.ToCIDR.String()
				}
				label := p.Label
				if label == "" {
					label = to.Name
				}
				cfg.Access = append(cfg.Access, AccessTarget{Label: label, Target: target, Proto: string(p.Proto), Ports: p.Ports})
			}
		}
		if cfg.Access == nil {
			cfg.Access = []AccessTarget{}
		}
		return nil
	})
	return cfg, err
}

// AuthenticateDevice resolves a bearer token to a device (any status).
func (s *Service) AuthenticateDevice(ctx context.Context, token string) (store.Device, error) {
	var d store.Device
	if !strings.HasPrefix(token, "dnd_") {
		return d, ErrAccessDenied
	}
	err := s.db.View(ctx, func(tx *store.Tx) error {
		var err error
		d, err = tx.GetDeviceByTokenHash(auth.HashToken(token))
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return d, ErrAccessDenied
	}
	return d, err
}

func (s *Service) Heartbeat(ctx context.Context, deviceID int64, clientVersion string) error {
	if len(clientVersion) > 32 {
		clientVersion = clientVersion[:32]
	}
	return s.db.Tx(ctx, func(tx *store.Tx) error { return tx.TouchDevice(deviceID, clientVersion) })
}

// RotateKey replaces a device's public key and re-provisions.
func (s *Service) RotateKey(ctx context.Context, deviceID int64, newKey, remoteIP string) error {
	k, err := wgtypes.ParseKey(strings.TrimSpace(newKey))
	if err != nil {
		return ErrBadPublicKey
	}
	var job store.Job
	err = s.db.Tx(ctx, func(tx *store.Tx) error {
		d, err := tx.GetDevice(deviceID)
		if err != nil {
			return err
		}
		if d.Status != store.DeviceActive {
			return ErrDeviceRevoked
		}
		if err := tx.UpdateDevicePublicKey(d.ID, k.String()); errors.Is(err, store.ErrDuplicateKey) {
			return ErrDuplicateKey
		} else if err != nil {
			return err
		}
		job, err = tx.InsertJob(store.Job{CustomerID: d.CustomerID, DeviceID: d.ID, PublicKey: k.String(), Action: store.JobUpdate})
		if err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "device", ActorID: fmt.Sprintf("%d", d.ID), Action: "device.rotate_key", Target: fmt.Sprintf("device:%d", d.ID), IP: remoteIP})
	})
	if err != nil {
		return err
	}
	if err := s.applyJob(ctx, job); err != nil {
		return ErrProvisioning
	}
	return nil
}

// ---------- revocation ----------

func (s *Service) RevokeDevice(ctx context.Context, deviceID int64, reason, actor string) error {
	var job store.Job
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		d, err := tx.GetDevice(deviceID)
		if err != nil {
			return err
		}
		if err := tx.RevokeDevice(d.ID, reason); err != nil {
			return err
		}
		if err := tx.BumpCustomerConfigVersion(d.CustomerID); err != nil {
			return err
		}
		job, err = tx.InsertJob(store.Job{CustomerID: d.CustomerID, DeviceID: d.ID, PublicKey: d.PublicKey, Action: store.JobRemove})
		if err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "device.revoke", Target: fmt.Sprintf("device:%d", d.ID), Detail: reason})
	})
	if err != nil {
		return err
	}
	return s.applyJob(ctx, job)
}

// ---------- policies ----------

type NewPolicy struct {
	CustomerID   int64
	FromDeviceID int64
	ToDeviceID   int64
	ToCIDR       netip.Prefix
	Proto        store.Proto
	Ports        []int
	Label        string
	AllowSMB     bool
	Actor        string
}

func (s *Service) CreatePolicy(ctx context.Context, in NewPolicy) (store.AccessPolicy, error) {
	var out store.AccessPolicy
	switch in.Proto {
	case store.ProtoTCP, store.ProtoUDP:
		if err := policy.ValidatePorts(in.Ports, in.AllowSMB); err != nil {
			return out, err
		}
	case store.ProtoICMP:
		in.Ports = nil
	default:
		return out, errors.New("protocol must be tcp, udp or icmp")
	}
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		to, err := tx.GetDevice(in.ToDeviceID)
		if err != nil {
			return err
		}
		if to.CustomerID != in.CustomerID {
			return ErrCrossTenant
		}
		if to.Role != store.RoleGateway {
			return ErrPolicyTargetRole
		}
		if in.ToCIDR.IsValid() {
			found := false
			for _, l := range to.LANSubnets {
				if l.Masked() == in.ToCIDR.Masked() {
					found = true
				}
			}
			if !found {
				return errors.New("target LAN is not declared by that gateway")
			}
		}
		if in.FromDeviceID != 0 {
			from, err := tx.GetDevice(in.FromDeviceID)
			if err != nil {
				return err
			}
			if from.CustomerID != in.CustomerID {
				return ErrCrossTenant
			}
		}
		out, err = tx.InsertPolicy(store.AccessPolicy{CustomerID: in.CustomerID, FromDeviceID: in.FromDeviceID, ToDeviceID: in.ToDeviceID, ToCIDR: in.ToCIDR, Proto: in.Proto, Ports: in.Ports, Label: in.Label, Enabled: true})
		if err != nil {
			return err
		}
		if err := tx.BumpCustomerConfigVersion(in.CustomerID); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: in.Actor, Action: "policy.create", Target: fmt.Sprintf("policy:%d", out.ID), Detail: fmt.Sprintf("customer=%d to=%d proto=%s ports=%v cidr=%s smb=%v", in.CustomerID, in.ToDeviceID, in.Proto, in.Ports, in.ToCIDR, in.AllowSMB)})
	})
	if err != nil {
		return out, err
	}
	return out, s.Apply(ctx, "policy created")
}

func (s *Service) SetPolicyEnabled(ctx context.Context, id int64, enabled bool, actor string) error {
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		p, err := tx.GetPolicy(id)
		if err != nil {
			return err
		}
		if err := tx.SetPolicyEnabled(id, enabled); err != nil {
			return err
		}
		if err := tx.BumpCustomerConfigVersion(p.CustomerID); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: fmt.Sprintf("policy.enabled=%v", enabled), Target: fmt.Sprintf("policy:%d", id)})
	})
	if err != nil {
		return err
	}
	return s.Apply(ctx, "policy toggled")
}

func (s *Service) DeletePolicy(ctx context.Context, id int64, actor string) error {
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		p, err := tx.GetPolicy(id)
		if err != nil {
			return err
		}
		if err := tx.DeletePolicy(id); err != nil {
			return err
		}
		if err := tx.BumpCustomerConfigVersion(p.CustomerID); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "policy.delete", Target: fmt.Sprintf("policy:%d", id)})
	})
	if err != nil {
		return err
	}
	return s.Apply(ctx, "policy deleted")
}

// ---------- applying state to the hub ----------

// Desired computes the full desired hub state from the database.
func (s *Service) Desired(ctx context.Context) (policy.Desired, error) {
	var in policy.Input
	err := s.db.View(ctx, func(tx *store.Tx) error {
		var err error
		if in.Customers, err = tx.ListCustomers(); err != nil {
			return err
		}
		if in.Devices, err = tx.ListAllDevices(); err != nil {
			return err
		}
		in.Policies, err = tx.ListAllPolicies()
		return err
	})
	in.Now = s.now()
	return policy.Compute(in), err
}

// Apply converges the hub to the database. Safe to call at any time from any
// goroutine; calls are serialised. reason is for the log only.
func (s *Service) Apply(ctx context.Context, reason string) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	return s.applyLocked(ctx, reason)
}

func (s *Service) applyLocked(ctx context.Context, reason string) error {
	desired, err := s.Desired(ctx)
	if err != nil {
		return err
	}
	// Order matters for safety: firewall first (tighten), then routes, then
	// peers. A failure part-way leaves the hub more restrictive, never less.
	rendered, err := firewall.Render(firewall.Spec{Interface: s.cfg.Interface, Rules: desired.Rules, HubAddresses: s.cfg.HubAddresses})
	if err != nil {
		return err
	}
	if err := s.fw.Apply(ctx, rendered); err != nil {
		return err
	}
	if s.router != nil {
		if err := s.router.EnsureRoutes(ctx, s.cfg.Interface, desired.Routes); err != nil {
			return err
		}
	}
	if err := s.wg.Sync(ctx, desired.Peers); err != nil {
		return err
	}
	s.log.Info("hub converged", "reason", reason, "peers", len(desired.Peers), "rules", len(desired.Rules), "routes", len(desired.Routes))
	return nil
}

func (s *Service) applyJob(ctx context.Context, job store.Job) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	applyErr := s.applyLocked(ctx, fmt.Sprintf("job %d %s", job.ID, job.Action))
	state, msg := store.JobApplied, ""
	if applyErr != nil {
		state, msg = store.JobFailed, applyErr.Error()
	}
	if err := s.db.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.FinishJob(job.ID, state, msg); err != nil {
			return err
		}
		if applyErr != nil {
			return tx.Audit(store.AuditEntry{ActorType: "system", ActorID: "provisioner", Action: "job.failed", Target: fmt.Sprintf("job:%d", job.ID), Detail: msg})
		}
		return nil
	}); err != nil {
		return err
	}
	return applyErr
}

// Reconcile is the periodic/boot convergence: re-apply desired state, retry
// failed jobs, and pull live stats into the database.
func (s *Service) Reconcile(ctx context.Context) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	applyErr := s.applyLocked(ctx, "reconcile")
	if applyErr == nil {
		// Jobs that failed earlier are now effectively applied.
		_ = s.db.Tx(ctx, func(tx *store.Tx) error {
			jobs, err := tx.ListJobs(500)
			if err != nil {
				return err
			}
			for _, j := range jobs {
				if j.State == store.JobFailed || j.State == store.JobPending {
					if err := tx.FinishJob(j.ID, store.JobApplied, "recovered by reconcile"); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	stats, err := s.wg.Stats(ctx)
	if err == nil {
		_ = s.db.Tx(ctx, func(tx *store.Tx) error {
			for _, st := range stats {
				if err := tx.UpdateDeviceStats(st.PublicKey, st.LastHandshake, st.Endpoint, st.RxBytes, st.TxBytes); err != nil {
					return err
				}
			}
			return tx.PurgeExpiredSessions()
		})
	}
	return applyErr
}

// RunReconciler blocks, reconciling every interval until ctx is done.
func (s *Service) RunReconciler(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Reconcile(ctx); err != nil {
			s.log.Error("reconcile failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SortedRules is a helper for tests and the dashboard.
func SortedRules(r []firewall.Rule) []firewall.Rule {
	out := append([]firewall.Rule(nil), r...)
	sort.Slice(out, func(i, j int) bool { return out[i].Src.Less(out[j].Src) })
	return out
}
