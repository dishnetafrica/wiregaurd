package firewall

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sample() Spec {
	return Spec{
		Interface:    "wg0",
		HubAddresses: []netip.Addr{netip.MustParseAddr("10.20.0.1")},
		Rules: []Rule{
			{CustomerID: 2, Label: "default B server", Src: netip.MustParseAddr("10.20.0.34"), Dst: netip.MustParsePrefix("10.20.0.33/32"), Proto: "tcp", Ports: []int{3389}},
			{CustomerID: 1, Label: "default A server", Src: netip.MustParseAddr("10.20.0.18"), Dst: netip.MustParsePrefix("10.20.0.17/32"), Proto: "tcp", Ports: []int{9000, 3389}},
			{CustomerID: 1, Label: "lan", Src: netip.MustParseAddr("10.20.0.18"), Dst: netip.MustParsePrefix("192.168.10.0/24"), Proto: "icmp"},
		},
	}
}

func TestRenderGolden(t *testing.T) {
	got, err := Render(sample())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/golden.nft")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("rendered firewall differs from testdata/golden.nft:\n%s", got)
	}
}

func TestRenderIsDefaultDenyAndSorted(t *testing.T) {
	out, _ := Render(sample())
	if !strings.Contains(out, "type filter hook forward priority filter; policy accept;") {
		t.Fatal("forward base chain must not change the policy for non-VPN interfaces")
	}
	if !strings.Contains(out, `iifname "wg0" goto vpn_from_peer`) || !strings.Contains(out, `counter drop comment "dishnet default deny"`) {
		t.Fatal("VPN traffic must land in a default-deny chain")
	}
	a := strings.Index(out, "ip saddr 10.20.0.18 ip daddr 10.20.0.17")
	b := strings.Index(out, "ip saddr 10.20.0.34")
	if a < 0 || b < 0 || a > b {
		t.Fatal("rules must be sorted by customer for stable diffs")
	}
	if !strings.Contains(out, "tcp dport { 3389, 9000 }") {
		t.Fatal("ports must be sorted")
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	bad := []Spec{
		{Interface: "wg0; rm -rf /"},
		{Interface: "wg0", Rules: []Rule{{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParsePrefix("10.0.0.2/32"), Proto: "tcp"}}},
		{Interface: "wg0", Rules: []Rule{{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParsePrefix("10.0.0.2/32"), Proto: "tcp", Ports: []int{70000}}}},
		{Interface: "wg0", Rules: []Rule{{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParsePrefix("10.0.0.2/32"), Proto: "sctp", Ports: []int{1}}}},
	}
	for i, s := range bad {
		if _, err := Render(s); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
	out, _ := Render(Spec{Interface: "wg0", Rules: []Rule{{Label: "x\"; drop; #", Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParsePrefix("10.0.0.2/32"), Proto: "tcp", Ports: []int{1}}}})
	if strings.Contains(out, `"; drop`) || strings.Contains(out, "#\"") {
		t.Fatalf("comment not sanitised:\n%s", out)
	}
}

// If the nft binary is available, make sure the generated file parses.
func TestRenderedFileParsesWithNft(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	out, _ := Render(sample())
	path := filepath.Join(t.TempDir(), "dishnet.nft")
	os.WriteFile(path, []byte(out), 0o644)
	res, err := exec.CommandContext(context.Background(), nft, "-c", "-f", path).CombinedOutput()
	if err != nil {
		msg := string(res)
		if strings.Contains(msg, "Operation not permitted") || strings.Contains(msg, "Permission denied") || strings.Contains(msg, "Protocol not supported") || strings.Contains(msg, "No such file or directory") {
			t.Skipf("nft check needs netlink access: %s", strings.TrimSpace(msg))
		}
		t.Fatalf("nft -c rejected the generated file: %v\n%s\n%s", err, msg, out)
	}
}
