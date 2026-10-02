// Package policy validates access policies and LAN declarations and turns
// the database state into the concrete desired state of the hub: the peer
// list (with allowed IPs), the firewall rules and the kernel routes.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/ipam"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

// Ports that are never allowed through a template and need an explicit,
// audited override: SMB/NetBIOS expose raw Tally/ERP data files.
var BlockedByDefault = map[int]string{445: "SMB", 139: "NetBIOS", 137: "NetBIOS", 138: "NetBIOS"}

var rfc1918 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// Templates offered by the admin UI.
var Templates = map[string][]int{
	"rdp":       {3389},
	"tally":     {9000},
	"rdp_tally": {3389, 9000},
	"https":     {443},
	"sql":       {1433},
}

// ValidatePorts rejects out-of-range ports and (unless allowSensitive) the
// SMB family.
func ValidatePorts(ports []int, allowSensitive bool) error {
	if len(ports) == 0 {
		return errors.New("policy: at least one port is required")
	}
	if len(ports) > 32 {
		return errors.New("policy: too many ports in one rule")
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("policy: port %d out of range", p)
		}
		if name, bad := BlockedByDefault[p]; bad && !allowSensitive {
			return fmt.Errorf("policy: port %d (%s) is blocked by default; file shares must not cross the VPN", p, name)
		}
	}
	return nil
}

// ValidateLAN checks a gateway's office LAN declaration against the pools and
// every other customer's declared LANs.
func ValidateLAN(lan netip.Prefix, customerID int64, pools []store.Pool, others []store.Device) error {
	if !lan.IsValid() || !lan.Addr().Is4() {
		return errors.New("policy: LAN must be an IPv4 prefix")
	}
	if lan.Bits() < 16 {
		return errors.New("policy: LAN prefix must be /16 or smaller")
	}
	private := false
	for _, p := range rfc1918 {
		if p.Contains(lan.Addr()) {
			private = true
		}
	}
	if !private {
		return errors.New("policy: LAN must be an RFC 1918 private range")
	}
	for _, p := range pools {
		if ipam.Overlaps(lan, p.CIDR) {
			return fmt.Errorf("policy: LAN %s overlaps VPN pool %s", lan, p.CIDR)
		}
	}
	for _, d := range others {
		if d.CustomerID == customerID || d.Status != store.DeviceActive {
			continue
		}
		for _, o := range d.LANSubnets {
			if ipam.Overlaps(lan, o) {
				return fmt.Errorf("policy: LAN %s overlaps a range already routed for another customer", lan)
			}
		}
	}
	return nil
}

// Desired is the complete state the hub must be in.
type Desired struct {
	Peers  []wg.Peer
	Rules  []firewall.Rule
	Routes []netip.Prefix // office LANs reachable via wg0
}

// Input is a snapshot of the database.
type Input struct {
	Customers []store.Customer
	Devices   []store.Device
	Policies  []store.AccessPolicy
	Now       time.Time
}

// Compute derives the desired hub state. A device is provisioned only if it
// is active AND its customer is active and not expired; everything else is
// absent, which is what revocation, suspension and expiry rely on.
func Compute(in Input) Desired {
	cust := map[int64]store.Customer{}
	for _, c := range in.Customers {
		cust[c.ID] = c
	}
	live := map[int64]store.Device{}
	var peers []wg.Peer
	var routes []netip.Prefix
	for _, d := range in.Devices {
		c, ok := cust[d.CustomerID]
		if !ok || d.Status != store.DeviceActive || !c.Serviceable(in.Now) {
			continue
		}
		live[d.ID] = d
		allowed := []netip.Prefix{netip.PrefixFrom(d.VPNIP, 32)}
		if d.Role == store.RoleGateway {
			for _, lan := range d.LANSubnets {
				allowed = append(allowed, lan.Masked())
				routes = append(routes, lan.Masked())
			}
		}
		peers = append(peers, wg.Peer{PublicKey: d.PublicKey, AllowedIPs: allowed})
	}

	var rules []firewall.Rule
	for _, p := range in.Policies {
		if !p.Enabled {
			continue
		}
		to, ok := live[p.ToDeviceID]
		if !ok || to.CustomerID != p.CustomerID {
			continue // target revoked/expired, or (defensively) cross-tenant
		}
		dst := netip.PrefixFrom(to.VPNIP, 32)
		if p.ToCIDR.IsValid() {
			if to.Role != store.RoleGateway || !declares(to, p.ToCIDR) {
				continue // a LAN rule is only valid towards a gateway that declared that LAN
			}
			dst = p.ToCIDR.Masked()
		}
		var sources []store.Device
		if p.FromDeviceID != 0 {
			if from, ok := live[p.FromDeviceID]; ok && from.CustomerID == p.CustomerID {
				sources = append(sources, from)
			}
		} else {
			for _, d := range in.Devices {
				if l, ok := live[d.ID]; ok && l.CustomerID == p.CustomerID && l.Role == store.RoleClient {
					sources = append(sources, l)
				}
			}
		}
		for _, src := range sources {
			if src.ID == to.ID {
				continue
			}
			rules = append(rules, firewall.Rule{
				CustomerID: p.CustomerID,
				Label:      p.Label,
				Src:        src.VPNIP,
				Dst:        dst,
				Proto:      string(p.Proto),
				Ports:      append([]int(nil), p.Ports...),
			})
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	return Desired{Peers: peers, Rules: rules, Routes: dedupe(routes)}
}

func declares(gw store.Device, lan netip.Prefix) bool {
	for _, l := range gw.LANSubnets {
		if l.Masked() == lan.Masked() {
			return true
		}
	}
	return false
}

func dedupe(p []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, x := range p {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

// ClientAllowedIPs is what a device's own configuration must route into the
// tunnel: for a client, the addresses it is allowed to reach; for a gateway,
// its customer's whole block so replies to clients go back into the tunnel.
func ClientAllowedIPs(d store.Device, c store.Customer, devices []store.Device, policies []store.AccessPolicy) []netip.Prefix {
	if d.Role == store.RoleGateway {
		return []netip.Prefix{c.VPNBlock.Masked()}
	}
	byID := map[int64]store.Device{}
	for _, x := range devices {
		byID[x.ID] = x
	}
	var out []netip.Prefix
	for _, p := range policies {
		if !p.Enabled || p.CustomerID != d.CustomerID {
			continue
		}
		if p.FromDeviceID != 0 && p.FromDeviceID != d.ID {
			continue
		}
		to, ok := byID[p.ToDeviceID]
		if !ok || to.Status != store.DeviceActive {
			continue
		}
		if p.ToCIDR.IsValid() {
			out = append(out, p.ToCIDR.Masked())
		} else {
			out = append(out, netip.PrefixFrom(to.VPNIP, 32))
		}
	}
	return dedupe(out)
}
