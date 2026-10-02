package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ---------- helpers ----------

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, p := range v {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

func splitInts(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func prefixesJSON(p []netip.Prefix) string {
	ss := make([]string, len(p))
	for i, x := range p {
		ss[i] = x.String()
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

func parsePrefixesJSON(s string) []netip.Prefix {
	var ss []string
	_ = json.Unmarshal([]byte(s), &ss)
	out := make([]netip.Prefix, 0, len(ss))
	for _, x := range ss {
		if p, err := netip.ParsePrefix(x); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func intsJSON(v []int) string {
	if v == nil {
		v = []int{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func parseIntsJSON(s string) []int {
	var v []int
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

// ---------- pools ----------

func (t *Tx) InsertPool(name string, cidr netip.Prefix, blockLen int) (Pool, error) {
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO address_pools(name, cidr, block_len, created_at) VALUES (?,?,?,?)`,
		name, cidr.Masked().String(), blockLen, Now())
	if err != nil {
		return Pool{}, err
	}
	id, _ := res.LastInsertId()
	return Pool{ID: id, Name: name, CIDR: cidr.Masked(), BlockLen: blockLen}, nil
}

func (t *Tx) ListPools() ([]Pool, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT id, name, cidr, block_len FROM address_pools ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pool
	for rows.Next() {
		var p Pool
		var cidr string
		if err := rows.Scan(&p.ID, &p.Name, &cidr, &p.BlockLen); err != nil {
			return nil, err
		}
		p.CIDR, _ = netip.ParsePrefix(cidr)
		out = append(out, p)
	}
	return out, rows.Err()
}

// UsedBlocks returns every customer block allocated from the pool.
func (t *Tx) UsedBlocks(poolID int64) ([]netip.Prefix, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT vpn_block FROM customers WHERE pool_id=?`, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Prefix
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// ---------- customers ----------

const customerCols = `id, name, contact, status, plan, subscription_expires_at, device_limit, default_ports, vpn_block, pool_id, created_at, updated_at`

func scanCustomer(sc interface{ Scan(...any) error }) (Customer, error) {
	var c Customer
	var exp sql.NullString
	var ports, block, created, updated string
	if err := sc.Scan(&c.ID, &c.Name, &c.Contact, (*string)(&c.Status), (*string)(&c.Plan), &exp, &c.DeviceLimit, &ports, &block, &c.PoolID, &created, &updated); err != nil {
		return c, err
	}
	c.SubscriptionExpiresAt = ParseTime(exp)
	c.DefaultPorts = splitInts(ports)
	c.VPNBlock, _ = netip.ParsePrefix(block)
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return c, nil
}

func (t *Tx) InsertCustomer(c Customer) (Customer, error) {
	now := Now()
	if c.Plan == "" {
		c.Plan = PlanPaid
	}
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO customers(name, contact, status, plan, subscription_expires_at, device_limit, default_ports, vpn_block, pool_id, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		c.Name, c.Contact, string(CustomerActive), string(c.Plan), nullTime(c.SubscriptionExpiresAt), c.DeviceLimit, joinInts(c.DefaultPorts), c.VPNBlock.Masked().String(), c.PoolID, now, now)
	if err != nil {
		return c, err
	}
	c.ID, _ = res.LastInsertId()
	return t.GetCustomer(c.ID)
}

func (t *Tx) GetCustomer(id int64) (Customer, error) {
	c, err := scanCustomer(t.tx.QueryRowContext(t.ctx, `SELECT `+customerCols+` FROM customers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func (t *Tx) ListCustomers() ([]Customer, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT `+customerCols+` FROM customers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Customer
	for rows.Next() {
		c, err := scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (t *Tx) UpdateCustomer(c Customer) error {
	_, err := t.tx.ExecContext(t.ctx, `UPDATE customers SET name=?, contact=?, status=?, plan=?, subscription_expires_at=?, device_limit=?, default_ports=?, updated_at=? WHERE id=?`,
		c.Name, c.Contact, string(c.Status), string(c.Plan), nullTime(c.SubscriptionExpiresAt), c.DeviceLimit, joinInts(c.DefaultPorts), Now(), c.ID)
	return err
}

// ---------- activation codes ----------

const codeCols = `id, customer_id, code_hash, code_hint, role, label, max_uses, uses, expires_at, revoked_at, created_by, created_at`

func scanCode(sc interface{ Scan(...any) error }) (ActivationCode, error) {
	var c ActivationCode
	var exp, rev sql.NullString
	var created string
	if err := sc.Scan(&c.ID, &c.CustomerID, &c.CodeHash, &c.CodeHint, (*string)(&c.Role), &c.Label, &c.MaxUses, &c.Uses, &exp, &rev, &c.CreatedBy, &created); err != nil {
		return c, err
	}
	c.ExpiresAt = ParseTime(exp)
	c.RevokedAt = ParseTime(rev)
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return c, nil
}

func (t *Tx) InsertCode(c ActivationCode) (ActivationCode, error) {
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO activation_codes(customer_id, code_hash, code_hint, role, label, max_uses, uses, expires_at, created_by, created_at)
		VALUES (?,?,?,?,?,?,0,?,?,?)`,
		c.CustomerID, c.CodeHash, c.CodeHint, string(c.Role), c.Label, c.MaxUses, nullTime(c.ExpiresAt), c.CreatedBy, Now())
	if err != nil {
		return c, err
	}
	c.ID, _ = res.LastInsertId()
	return c, nil
}

func (t *Tx) GetCodeByHash(hash string) (ActivationCode, error) {
	c, err := scanCode(t.tx.QueryRowContext(t.ctx, `SELECT `+codeCols+` FROM activation_codes WHERE code_hash=?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func (t *Tx) GetCode(id int64) (ActivationCode, error) {
	c, err := scanCode(t.tx.QueryRowContext(t.ctx, `SELECT `+codeCols+` FROM activation_codes WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func (t *Tx) ListCodes(customerID int64) ([]ActivationCode, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT `+codeCols+` FROM activation_codes WHERE customer_id=? ORDER BY id DESC`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActivationCode
	for rows.Next() {
		c, err := scanCode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ConsumeCode increments uses if, and only if, the code is still below its
// limit. Returns false when another transaction got there first.
func (t *Tx) ConsumeCode(id int64) (bool, error) {
	res, err := t.tx.ExecContext(t.ctx, `UPDATE activation_codes SET uses = uses + 1 WHERE id=? AND uses < max_uses AND revoked_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (t *Tx) RevokeCode(id int64) error {
	_, err := t.tx.ExecContext(t.ctx, `UPDATE activation_codes SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, Now(), id)
	return err
}

// ---------- devices ----------

const deviceCols = `id, customer_id, code_id, name, role, public_key, vpn_ip, lan_subnets, status, device_token_hash, os, client_version, config_version,
	last_seen_at, last_handshake_at, endpoint, rx_bytes, tx_bytes, registered_at, revoked_at, revoked_reason`

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var codeID sql.NullInt64
	var ip, lans, registered string
	var seen, hs, rev sql.NullString
	if err := sc.Scan(&d.ID, &d.CustomerID, &codeID, &d.Name, (*string)(&d.Role), &d.PublicKey, &ip, &lans, (*string)(&d.Status), &d.DeviceTokenHash, &d.OS, &d.ClientVersion, &d.ConfigVersion,
		&seen, &hs, &d.Endpoint, &d.RxBytes, &d.TxBytes, &registered, &rev, &d.RevokedReason); err != nil {
		return d, err
	}
	d.CodeID = codeID.Int64
	d.VPNIP, _ = netip.ParseAddr(ip)
	d.LANSubnets = parsePrefixesJSON(lans)
	d.LastSeenAt = ParseTime(seen)
	d.LastHandshakeAt = ParseTime(hs)
	d.RegisteredAt, _ = time.Parse(time.RFC3339, registered)
	d.RevokedAt = ParseTime(rev)
	return d, nil
}

var ErrDuplicateKey = errors.New("store: public key already registered")

func (t *Tx) InsertDevice(d Device) (Device, error) {
	var codeID any
	if d.CodeID != 0 {
		codeID = d.CodeID
	}
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO devices(customer_id, code_id, name, role, public_key, vpn_ip, lan_subnets, status, device_token_hash, os, client_version, config_version, registered_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)`,
		d.CustomerID, codeID, d.Name, string(d.Role), d.PublicKey, d.VPNIP.String(), prefixesJSON(d.LANSubnets), string(DeviceActive), d.DeviceTokenHash, d.OS, d.ClientVersion, Now())
	if err != nil {
		if isUnique(err) && strings.Contains(err.Error(), "public_key") {
			return d, ErrDuplicateKey
		}
		return d, err
	}
	d.ID, _ = res.LastInsertId()
	return t.GetDevice(d.ID)
}

func (t *Tx) GetDevice(id int64) (Device, error) {
	d, err := scanDevice(t.tx.QueryRowContext(t.ctx, `SELECT `+deviceCols+` FROM devices WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func (t *Tx) GetDeviceByTokenHash(hash string) (Device, error) {
	d, err := scanDevice(t.tx.QueryRowContext(t.ctx, `SELECT `+deviceCols+` FROM devices WHERE device_token_hash=?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func (t *Tx) GetDeviceByPublicKey(key string) (Device, error) {
	d, err := scanDevice(t.tx.QueryRowContext(t.ctx, `SELECT `+deviceCols+` FROM devices WHERE public_key=?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func (t *Tx) listDevices(where string, args ...any) ([]Device, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT `+deviceCols+` FROM devices `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (t *Tx) ListDevices(customerID int64) ([]Device, error) {
	return t.listDevices(`WHERE customer_id=? ORDER BY id`, customerID)
}

func (t *Tx) ListAllDevices() ([]Device, error) {
	return t.listDevices(`ORDER BY customer_id, id`)
}

// UsedAddresses returns every VPN address allocated in the customer's block,
// including revoked devices (addresses are not recycled until the device row
// is purged, so a revoked key can never be confused with a new device).
func (t *Tx) UsedAddresses(customerID int64) ([]netip.Addr, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT vpn_ip FROM devices WHERE customer_id=?`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Addr
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

func (t *Tx) CountActiveDevices(customerID int64) (int, error) {
	var n int
	err := t.tx.QueryRowContext(t.ctx, `SELECT COUNT(*) FROM devices WHERE customer_id=? AND status='active'`, customerID).Scan(&n)
	return n, err
}

func (t *Tx) RevokeDevice(id int64, reason string) error {
	res, err := t.tx.ExecContext(t.ctx, `UPDATE devices SET status='revoked', revoked_at=?, revoked_reason=?, config_version=config_version+1 WHERE id=? AND status='active'`, Now(), reason, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (t *Tx) UpdateDevicePublicKey(id int64, key string) error {
	_, err := t.tx.ExecContext(t.ctx, `UPDATE devices SET public_key=?, config_version=config_version+1 WHERE id=?`, key, id)
	if isUnique(err) {
		return ErrDuplicateKey
	}
	return err
}

func (t *Tx) TouchDevice(id int64, clientVersion string) error {
	_, err := t.tx.ExecContext(t.ctx, `UPDATE devices SET last_seen_at=?, client_version=? WHERE id=?`, Now(), clientVersion, id)
	return err
}

// BumpCustomerConfigVersion tells every device of the customer to refetch its
// configuration (used when policies or gateways change).
func (t *Tx) BumpCustomerConfigVersion(customerID int64) error {
	_, err := t.tx.ExecContext(t.ctx, `UPDATE devices SET config_version=config_version+1 WHERE customer_id=?`, customerID)
	return err
}

func (t *Tx) UpdateDeviceStats(publicKey string, handshake time.Time, endpoint string, rx, tx int64) error {
	_, err := t.tx.ExecContext(t.ctx, `UPDATE devices SET last_handshake_at=?, endpoint=?, rx_bytes=?, tx_bytes=? WHERE public_key=?`,
		nullTime(handshake), endpoint, rx, tx, publicKey)
	return err
}

// ---------- policies ----------

const policyCols = `id, customer_id, from_device_id, to_device_id, to_cidr, proto, ports, label, enabled, created_at`

func scanPolicy(sc interface{ Scan(...any) error }) (AccessPolicy, error) {
	var p AccessPolicy
	var from sql.NullInt64
	var cidr sql.NullString
	var ports, created string
	var enabled int
	if err := sc.Scan(&p.ID, &p.CustomerID, &from, &p.ToDeviceID, &cidr, (*string)(&p.Proto), &ports, &p.Label, &enabled, &created); err != nil {
		return p, err
	}
	p.FromDeviceID = from.Int64
	if cidr.Valid && cidr.String != "" {
		p.ToCIDR, _ = netip.ParsePrefix(cidr.String)
	}
	p.Ports = parseIntsJSON(ports)
	p.Enabled = enabled == 1
	p.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return p, nil
}

func (t *Tx) InsertPolicy(p AccessPolicy) (AccessPolicy, error) {
	var from, cidr any
	if p.FromDeviceID != 0 {
		from = p.FromDeviceID
	}
	if p.ToCIDR.IsValid() {
		cidr = p.ToCIDR.String()
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO access_policies(customer_id, from_device_id, to_device_id, to_cidr, proto, ports, label, enabled, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, p.CustomerID, from, p.ToDeviceID, cidr, string(p.Proto), intsJSON(p.Ports), p.Label, enabled, Now())
	if err != nil {
		return p, err
	}
	p.ID, _ = res.LastInsertId()
	return p, nil
}

func (t *Tx) GetPolicy(id int64) (AccessPolicy, error) {
	p, err := scanPolicy(t.tx.QueryRowContext(t.ctx, `SELECT `+policyCols+` FROM access_policies WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (t *Tx) SetPolicyEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := t.tx.ExecContext(t.ctx, `UPDATE access_policies SET enabled=? WHERE id=?`, v, id)
	return err
}

func (t *Tx) DeletePolicy(id int64) error {
	_, err := t.tx.ExecContext(t.ctx, `DELETE FROM access_policies WHERE id=?`, id)
	return err
}

func (t *Tx) listPolicies(where string, args ...any) ([]AccessPolicy, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT `+policyCols+` FROM access_policies `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (t *Tx) ListPolicies(customerID int64) ([]AccessPolicy, error) {
	return t.listPolicies(`WHERE customer_id=? ORDER BY id`, customerID)
}

func (t *Tx) ListAllPolicies() ([]AccessPolicy, error) {
	return t.listPolicies(`ORDER BY customer_id, id`)
}

// ---------- jobs ----------

const jobCols = `id, customer_id, device_id, public_key, action, state, error, attempts, created_at, applied_at`

func scanJob(sc interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var dev sql.NullInt64
	var created string
	var applied sql.NullString
	if err := sc.Scan(&j.ID, &j.CustomerID, &dev, &j.PublicKey, (*string)(&j.Action), (*string)(&j.State), &j.Error, &j.Attempts, &created, &applied); err != nil {
		return j, err
	}
	j.DeviceID = dev.Int64
	j.CreatedAt, _ = time.Parse(time.RFC3339, created)
	j.AppliedAt = ParseTime(applied)
	return j, nil
}

func (t *Tx) InsertJob(j Job) (Job, error) {
	var dev any
	if j.DeviceID != 0 {
		dev = j.DeviceID
	}
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO provisioning_jobs(customer_id, device_id, public_key, action, state, created_at) VALUES (?,?,?,?,'pending',?)`,
		j.CustomerID, dev, j.PublicKey, string(j.Action), Now())
	if err != nil {
		return j, err
	}
	j.ID, _ = res.LastInsertId()
	j.State = JobPending
	return j, nil
}

func (t *Tx) FinishJob(id int64, state JobState, errMsg string) error {
	var applied any
	if state == JobApplied {
		applied = Now()
	}
	_, err := t.tx.ExecContext(t.ctx, `UPDATE provisioning_jobs SET state=?, error=?, attempts=attempts+1, applied_at=? WHERE id=?`, string(state), errMsg, applied, id)
	return err
}

func (t *Tx) ListJobs(limit int) ([]Job, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT `+jobCols+` FROM provisioning_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (t *Tx) CountJobs(state JobState) (int, error) {
	var n int
	err := t.tx.QueryRowContext(t.ctx, `SELECT COUNT(*) FROM provisioning_jobs WHERE state=?`, string(state)).Scan(&n)
	return n, err
}

// ---------- admins & sessions ----------

func (t *Tx) InsertAdmin(a Admin) (Admin, error) {
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO admins(email, password_hash, role, created_at) VALUES (?,?,?,?)`, strings.ToLower(a.Email), a.PasswordHash, string(a.Role), Now())
	if err != nil {
		if isUnique(err) {
			return a, fmt.Errorf("store: admin %s already exists", a.Email)
		}
		return a, err
	}
	a.ID, _ = res.LastInsertId()
	return a, nil
}

func scanAdmin(sc interface{ Scan(...any) error }) (Admin, error) {
	var a Admin
	var disabled int
	var created string
	if err := sc.Scan(&a.ID, &a.Email, &a.PasswordHash, (*string)(&a.Role), &disabled, &created); err != nil {
		return a, err
	}
	a.Disabled = disabled == 1
	a.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return a, nil
}

func (t *Tx) GetAdminByEmail(email string) (Admin, error) {
	a, err := scanAdmin(t.tx.QueryRowContext(t.ctx, `SELECT id, email, password_hash, role, disabled, created_at FROM admins WHERE email=?`, strings.ToLower(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (t *Tx) GetAdmin(id int64) (Admin, error) {
	a, err := scanAdmin(t.tx.QueryRowContext(t.ctx, `SELECT id, email, password_hash, role, disabled, created_at FROM admins WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (t *Tx) ListAdmins() ([]Admin, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT id, email, password_hash, role, disabled, created_at FROM admins ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (t *Tx) InsertSession(s AdminSession) error {
	_, err := t.tx.ExecContext(t.ctx, `INSERT INTO admin_sessions(token_hash, admin_id, csrf_token, expires_at, created_at) VALUES (?,?,?,?,?)`,
		s.TokenHash, s.AdminID, s.CSRFToken, s.ExpiresAt.UTC().Format(time.RFC3339), Now())
	return err
}

func (t *Tx) GetSession(tokenHash string) (AdminSession, error) {
	var s AdminSession
	var exp string
	err := t.tx.QueryRowContext(t.ctx, `SELECT token_hash, admin_id, csrf_token, expires_at FROM admin_sessions WHERE token_hash=?`, tokenHash).Scan(&s.TokenHash, &s.AdminID, &s.CSRFToken, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	s.ExpiresAt, _ = time.Parse(time.RFC3339, exp)
	return s, nil
}

func (t *Tx) DeleteSession(tokenHash string) error {
	_, err := t.tx.ExecContext(t.ctx, `DELETE FROM admin_sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (t *Tx) PurgeExpiredSessions() error {
	_, err := t.tx.ExecContext(t.ctx, `DELETE FROM admin_sessions WHERE expires_at < ?`, Now())
	return err
}

// ---------- audit ----------

func (t *Tx) Audit(e AuditEntry) error {
	_, err := t.tx.ExecContext(t.ctx, `INSERT INTO audit_log(at, actor_type, actor_id, action, target, detail, ip) VALUES (?,?,?,?,?,?,?)`,
		Now(), e.ActorType, e.ActorID, e.Action, e.Target, e.Detail, e.IP)
	return err
}

func (t *Tx) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT id, at, actor_type, actor_id, action, target, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.ActorType, &e.ActorID, &e.Action, &e.Target, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, e)
	}
	return out, rows.Err()
}
