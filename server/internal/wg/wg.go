// Package wg manages peers on the hub's WireGuard interface through netlink
// (wgctrl). It never touches the interface's private key, listen port or
// address, and never executes a shell.
package wg

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer is the desired state of one hub-side peer.
type Peer struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
}

// Stats is the live state of a peer as reported by the kernel.
type Stats struct {
	PublicKey     string
	LastHandshake time.Time
	Endpoint      string
	RxBytes       int64
	TxBytes       int64
}

// Backend is implemented by the real interface and by the test fake.
type Backend interface {
	// PublicKey returns the hub's public key (read from the interface, never from disk).
	PublicKey(ctx context.Context) (string, error)
	// Sync makes the interface's peer set exactly equal to peers: missing peers
	// are added, extra peers removed, allowed IPs replaced. It is idempotent.
	Sync(ctx context.Context, peers []Peer) error
	// Stats reports handshake and transfer counters for every peer.
	Stats(ctx context.Context) ([]Stats, error)
}

// ---------- real implementation ----------

type Kernel struct {
	Interface string
}

func (k *Kernel) PublicKey(ctx context.Context) (string, error) {
	c, err := wgctrl.New()
	if err != nil {
		return "", fmt.Errorf("wg: open wgctrl: %w", err)
	}
	defer c.Close()
	dev, err := c.Device(k.Interface)
	if err != nil {
		return "", fmt.Errorf("wg: device %s: %w", k.Interface, err)
	}
	return dev.PublicKey.String(), nil
}

func (k *Kernel) Sync(ctx context.Context, peers []Peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wg: open wgctrl: %w", err)
	}
	defer c.Close()
	dev, err := c.Device(k.Interface)
	if err != nil {
		return fmt.Errorf("wg: device %s: %w", k.Interface, err)
	}
	desired := map[string]Peer{}
	for _, p := range peers {
		desired[p.PublicKey] = p
	}
	var cfgPeers []wgtypes.PeerConfig
	for _, existing := range dev.Peers {
		if _, keep := desired[existing.PublicKey.String()]; !keep {
			cfgPeers = append(cfgPeers, wgtypes.PeerConfig{PublicKey: existing.PublicKey, Remove: true})
		}
	}
	for _, p := range peers {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("wg: bad public key %q: %w", p.PublicKey, err)
		}
		cfgPeers = append(cfgPeers, wgtypes.PeerConfig{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        toIPNets(p.AllowedIPs),
		})
	}
	// ReplacePeers=false and no PrivateKey/ListenPort: only peers are touched.
	return c.ConfigureDevice(k.Interface, wgtypes.Config{Peers: cfgPeers})
}

func (k *Kernel) Stats(ctx context.Context) ([]Stats, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dev, err := c.Device(k.Interface)
	if err != nil {
		return nil, err
	}
	out := make([]Stats, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		s := Stats{PublicKey: p.PublicKey.String(), LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint != nil {
			s.Endpoint = p.Endpoint.String()
		}
		out = append(out, s)
	}
	return out, nil
}

// ---------- fake for tests and --dry-run ----------

type Fake struct {
	mu       sync.Mutex
	Key      string
	Peers    map[string]Peer
	stats    map[string]Stats
	FailNext error
	Syncs    int
}

func NewFake() *Fake {
	return &Fake{Key: "FAKEHUBKEY000000000000000000000000000000000=", Peers: map[string]Peer{}, stats: map[string]Stats{}}
}

func (f *Fake) PublicKey(ctx context.Context) (string, error) { return f.Key, nil }

func (f *Fake) Sync(ctx context.Context, peers []Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Syncs++
	if f.FailNext != nil {
		err := f.FailNext
		f.FailNext = nil
		return err
	}
	f.Peers = map[string]Peer{}
	for _, p := range peers {
		f.Peers[p.PublicKey] = p
	}
	return nil
}

func (f *Fake) Stats(ctx context.Context) ([]Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Stats
	for k := range f.Peers {
		if s, ok := f.stats[k]; ok {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func (f *Fake) SetStats(s Stats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats[s.PublicKey] = s
}

// Snapshot returns the peers sorted by key, for assertions.
func (f *Fake) Snapshot() []Peer {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Peer, 0, len(f.Peers))
	for _, p := range f.Peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out
}
