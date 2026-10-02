package ipam

import (
	"net/netip"
	"testing"
)

func TestBlocksAndCapacity(t *testing.T) {
	pool := netip.MustParsePrefix("10.20.0.0/24")
	b28, err := Blocks(pool, 28)
	if err != nil {
		t.Fatal(err)
	}
	if len(b28) != 16 {
		t.Fatalf("/24 should hold 16 /28 blocks, got %d", len(b28))
	}
	if b28[1].String() != "10.20.0.16/28" || b28[15].String() != "10.20.0.240/28" {
		t.Fatalf("unexpected blocks %v", b28)
	}
	if Capacity(b28[1]) != 14 {
		t.Fatalf("/28 capacity should be 14, got %d", Capacity(b28[1]))
	}
	b29, _ := Blocks(pool, 29)
	if len(b29) != 32 || Capacity(b29[1]) != 6 {
		t.Fatalf("/29: want 32 blocks of 6, got %d blocks of %d", len(b29), Capacity(b29[1]))
	}
}

func TestNextFreeBlockReservesInfrastructureAndFills(t *testing.T) {
	pool := netip.MustParsePrefix("10.20.0.0/24")
	var used []netip.Prefix
	for i := 0; i < 15; i++ {
		b, err := NextFreeBlock(pool, 28, used)
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		if b.String() == "10.20.0.0/28" {
			t.Fatal("infrastructure block must never be allocated")
		}
		used = append(used, b)
	}
	if _, err := NextFreeBlock(pool, 28, used); err != ErrPoolFull {
		t.Fatalf("16th allocation should fail with ErrPoolFull, got %v", err)
	}
}

func TestNextFreeHostSkipsEdges(t *testing.T) {
	block := netip.MustParsePrefix("10.20.0.16/28")
	var used []netip.Addr
	for i := 0; i < 14; i++ {
		a, err := NextFreeHost(block, used)
		if err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
		if a.String() == "10.20.0.16" || a.String() == "10.20.0.31" {
			t.Fatalf("edge address %s must not be assigned", a)
		}
		used = append(used, a)
	}
	if used[0].String() != "10.20.0.17" || used[13].String() != "10.20.0.30" {
		t.Fatalf("unexpected range %v", used)
	}
	if _, err := NextFreeHost(block, used); err != ErrBlockFull {
		t.Fatalf("want ErrBlockFull, got %v", err)
	}
}

func TestOverlaps(t *testing.T) {
	a := netip.MustParsePrefix("192.168.1.0/24")
	if !Overlaps(a, netip.MustParsePrefix("192.168.0.0/16")) {
		t.Fatal("expected overlap")
	}
	if Overlaps(a, netip.MustParsePrefix("192.168.2.0/24")) {
		t.Fatal("unexpected overlap")
	}
}
