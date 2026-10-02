package wg

import (
	"net"
	"net/netip"
)

func toIPNets(prefixes []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, 0, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		out = append(out, net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	return out
}
