package provision

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

// ---------- DishNet Web Desktop: customer users ----------

const CustomerPasswordMin = 10

var (
	ErrBadLogin     = errors.New("invalid login or password")
	ErrUserDisabled = errors.New("this account is disabled; contact DishNet")
	ErrNoWebAccess  = errors.New("browser access is not enabled for your business; contact DishNet")
	ErrNoOffice     = errors.New("no office computer is registered for your business yet")
	ErrBadTOTP      = errors.New("that code is not valid")
	loginRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{2,39}$`)
)

// SetWebAccess switches browser access on or off for a customer. Turning it
// off signs every user of the customer out.
func (s *Service) SetWebAccess(ctx context.Context, customerID int64, enabled bool, actor string) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		c, err := tx.GetCustomer(customerID)
		if err != nil {
			return err
		}
		c.WebAccess = enabled
		if err := tx.UpdateCustomer(c); err != nil {
			return err
		}
		if !enabled {
			users, _ := tx.ListCustomerUsers(customerID)
			for _, u := range users {
				if err := tx.DeleteDeskSessionsForUser(u.ID); err != nil {
					return err
				}
			}
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "webaccess.set", Target: fmt.Sprintf("customer:%d", customerID), Detail: fmt.Sprintf("enabled=%v", enabled)})
	})
}

// NewTempPassword returns a 12-character password from an unambiguous alphabet.
func NewTempPassword() (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// CreateCustomerUser creates a web desktop login for one person at the
// customer and returns the temporary password exactly once. The user must
// change it at first sign-in.
func (s *Service) CreateCustomerUser(ctx context.Context, customerID int64, login, displayName, actor string) (store.CustomerUser, string, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	if !loginRe.MatchString(login) {
		return store.CustomerUser{}, "", errors.New("login must be 3-40 characters: letters, digits, dot, dash, underscore or @")
	}
	temp, err := NewTempPassword()
	if err != nil {
		return store.CustomerUser{}, "", err
	}
	hash, err := auth.HashPasswordMin(temp, CustomerPasswordMin)
	if err != nil {
		return store.CustomerUser{}, "", err
	}
	var u store.CustomerUser
	err = s.db.Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.GetCustomer(customerID); err != nil {
			return err
		}
		u, err = tx.InsertCustomerUser(store.CustomerUser{CustomerID: customerID, Login: login, DisplayName: clipStr(displayName, 60), PasswordHash: hash, MustChangePassword: true, CreatedBy: actor})
		if err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "webuser.create", Target: fmt.Sprintf("user:%d", u.ID), Detail: fmt.Sprintf("customer=%d login=%s", customerID, login)})
	})
	return u, temp, err
}

// ResetCustomerUserPassword issues a new temporary password and signs the user out everywhere.
func (s *Service) ResetCustomerUserPassword(ctx context.Context, userID int64, actor string) (string, error) {
	temp, err := NewTempPassword()
	if err != nil {
		return "", err
	}
	hash, err := auth.HashPasswordMin(temp, CustomerPasswordMin)
	if err != nil {
		return "", err
	}
	return temp, s.db.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.GetCustomerUser(userID)
		if err != nil {
			return err
		}
		u.PasswordHash, u.MustChangePassword = hash, true
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		if err := tx.DeleteDeskSessionsForUser(u.ID); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "webuser.reset_password", Target: fmt.Sprintf("user:%d", u.ID)})
	})
}

func (s *Service) SetCustomerUserDisabled(ctx context.Context, userID int64, disabled bool, actor string) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.GetCustomerUser(userID)
		if err != nil {
			return err
		}
		u.Disabled = disabled
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		if disabled {
			if err := tx.DeleteDeskSessionsForUser(u.ID); err != nil {
				return err
			}
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "webuser.set_disabled", Target: fmt.Sprintf("user:%d", u.ID), Detail: fmt.Sprintf("disabled=%v", disabled)})
	})
}

// ClearCustomerUserTOTP removes two-factor (lost phone); the user can enrol again.
func (s *Service) ClearCustomerUserTOTP(ctx context.Context, userID int64, actor string) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.GetCustomerUser(userID)
		if err != nil {
			return err
		}
		u.TOTPSecret = ""
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		if err := tx.DeleteDeskSessionsForUser(u.ID); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "admin", ActorID: actor, Action: "webuser.clear_totp", Target: fmt.Sprintf("user:%d", u.ID)})
	})
}

// AuthenticateCustomerUser verifies a login/password and that the customer
// may use the web desktop. The error is deliberately the same for an unknown
// login and a wrong password.
func (s *Service) AuthenticateCustomerUser(ctx context.Context, login, password, ip string) (store.CustomerUser, store.Customer, error) {
	var u store.CustomerUser
	var c store.Customer
	err := s.db.Tx(ctx, func(tx *store.Tx) error {
		var err error
		u, err = tx.GetCustomerUserByLogin(login)
		if err != nil || !auth.VerifyPassword(u.PasswordHash, password) {
			_ = tx.Audit(store.AuditEntry{ActorType: "webuser", ActorID: strings.ToLower(strings.TrimSpace(login)), Action: "webuser.login_failed", IP: ip})
			return ErrBadLogin
		}
		if u.Disabled {
			return ErrUserDisabled
		}
		c, err = tx.GetCustomer(u.CustomerID)
		if err != nil {
			return err
		}
		if !c.WebAccess {
			return ErrNoWebAccess
		}
		if !c.Serviceable(s.now()) {
			return &DeniedError{reasonFor(c, s.now())}
		}
		u.LastLoginAt = s.now()
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "webuser", ActorID: u.Login, Action: "webuser.login", Target: fmt.Sprintf("customer:%d", c.ID), IP: ip})
	})
	return u, c, err
}

func reasonFor(c store.Customer, now time.Time) DeniedReason {
	if c.Status == store.CustomerSuspended {
		return DeniedSuspended
	}
	return DeniedExpired
}

func (s *Service) ChangeCustomerUserPassword(ctx context.Context, userID int64, current, next string) error {
	hash, err := auth.HashPasswordMin(next, CustomerPasswordMin)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.GetCustomerUser(userID)
		if err != nil {
			return err
		}
		if !auth.VerifyPassword(u.PasswordHash, current) {
			return errors.New("current password is wrong")
		}
		if current == next {
			return errors.New("choose a different password")
		}
		u.PasswordHash, u.MustChangePassword = hash, false
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "webuser", ActorID: u.Login, Action: "webuser.password_changed"})
	})
}

// EnableCustomerUserTOTP turns two-factor on once the user proves the app is set up with a valid code.
func (s *Service) EnableCustomerUserTOTP(ctx context.Context, userID int64, secret, code string) error {
	if !auth.VerifyTOTP(secret, code, s.now()) {
		return ErrBadTOTP
	}
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.GetCustomerUser(userID)
		if err != nil {
			return err
		}
		u.TOTPSecret = secret
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "webuser", ActorID: u.Login, Action: "webuser.totp_enabled"})
	})
}

func (s *Service) DisableCustomerUserTOTP(ctx context.Context, userID int64, code string) error {
	return s.db.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.GetCustomerUser(userID)
		if err != nil {
			return err
		}
		if u.TOTPSecret == "" || !auth.VerifyTOTP(u.TOTPSecret, code, s.now()) {
			return ErrBadTOTP
		}
		u.TOTPSecret = ""
		if err := tx.UpdateCustomerUser(u); err != nil {
			return err
		}
		return tx.Audit(store.AuditEntry{ActorType: "webuser", ActorID: u.Login, Action: "webuser.totp_disabled"})
	})
}

// OfficeTarget is the office computer a web desktop user of the customer may
// reach: the customer's active gateway that has an enabled any-client policy
// on the Remote Desktop port. Only that customer's rows are read.
type OfficeTarget struct {
	Device store.Device
	Online bool
	Port   int
}

const OnlineWindow = 3 * time.Minute

func (s *Service) OfficeTarget(ctx context.Context, customerID int64) (OfficeTarget, error) {
	var out OfficeTarget
	err := s.db.View(ctx, func(tx *store.Tx) error {
		devices, err := tx.ListDevices(customerID)
		if err != nil {
			return err
		}
		policies, err := tx.ListPolicies(customerID)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if d.Role != store.RoleGateway || d.Status != store.DeviceActive {
				continue
			}
			for _, p := range policies {
				if !p.Enabled || p.ToDeviceID != d.ID || p.FromDeviceID != 0 || p.Proto != store.ProtoTCP || p.ToCIDR.IsValid() {
					continue
				}
				for _, port := range p.Ports {
					if port == 3389 {
						out = OfficeTarget{Device: d, Online: !d.LastHandshakeAt.IsZero() && s.now().Sub(d.LastHandshakeAt) < OnlineWindow, Port: port}
						return nil
					}
				}
			}
		}
		return ErrNoOffice
	})
	return out, err
}

// RecordDeskConnect audits a browser session to the office computer. Never
// includes the Windows user name or password.
func (s *Service) RecordDeskConnect(ctx context.Context, u store.CustomerUser, target store.Device, ip, outcome string) {
	_ = s.db.Tx(ctx, func(tx *store.Tx) error {
		return tx.Audit(store.AuditEntry{ActorType: "webuser", ActorID: u.Login, Action: "webdesk.connect", Target: fmt.Sprintf("device:%d", target.ID), Detail: outcome, IP: ip})
	})
}
