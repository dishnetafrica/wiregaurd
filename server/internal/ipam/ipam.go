// Package ipam allocates customer blocks from address pools and device
// addresses from customer blocks. It is pure: the caller supplies what is
// already in use and persists the result inside its own transaction.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrPoolFull  = errors.New("ipam: no free block in pool")
	ErrBlockFull = errors.New("ipam: no free address in block")
)

// Blocks returns every /blockLen block inside pool, in address order.
func Blocks(pool netip.Prefix, blockLen int) ([]netip.Prefix, error) {
	pool = pool.Masked()
	if !pool.Addr().Is4() {
		return nil, fmt.Errorf("ipam: only IPv4 pools are supported")
	}
	if blockLen < pool.Bits() || blockLen > 30 {
		return nil, fmt.Errorf("ipam: block length /%d invalid for pool %s", blockLen, pool)
	}
	count := 1 << (blockLen - pool.Bits())
	step := uint32(1) << (32 - blockLen)
	out := make([]netip.Prefix, 0, count)
	base := addrToU32(pool.Addr())
	for i := 0; i < count; i++ {
		out = append(out, netip.PrefixFrom(u32ToAddr(base+uint32(i)*step), blockLen))
	}
	return out, nil
}

// NextFreeBlock returns the lowest block in pool that is neither used nor
// reserved. The first block of every pool is always reserved for
// infrastructure (it contains the hub address).
func NextFreeBlock(pool netip.Prefix, blockLen int, used []netip.Prefix) (netip.Prefix, error) {
	blocks, err := Blocks(pool, blockLen)
	if err != nil {
		return netip.Prefix{}, err
	}
	for i, b := range blocks {
		if i == 0 {
			continue // infrastructure block
		}
		if !containsPrefix(used, b) {
			return b, nil
		}
	}
	return netip.Prefix{}, ErrPoolFull
}

// Capacity is the number of device addresses a block can hold. The first and
// last address of the block are never assigned (see docs/address-plan.md).
func Capacity(block netip.Prefix) int {
	n := 1 << (32 - block.Bits())
	return n - 2
}

// NextFreeHost returns the lowest unused address in block, skipping the
// block's first and last address.
func NextFreeHost(block netip.Prefix, used []netip.Addr) (netip.Addr, error) {
	block = block.Masked()
	base := addrToU32(block.Addr())
	n := uint32(1) << (32 - block.Bits())
	for i := uint32(1); i < n-1; i++ {
		a := u32ToAddr(base + i)
		if !containsAddr(used, a) {
			return a, nil
		}
	}
	return netip.Addr{}, ErrBlockFull
}

// Overlaps reports whether two prefixes share any address.
func Overlaps(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, x := range list {
		if x.Masked() == p.Masked() {
			return true
		}
	}
	return false
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
