#!/usr/bin/env bash
# DishNet Secure Connect — read-only server audit + backup.
#
# Safe to run at any time: it changes NOTHING except writing a backup archive
# under /var/backups/dishnet/. Run as root on the hub:
#
#   sudo bash deploy/preflight.sh            # audit + backup
#   sudo bash deploy/preflight.sh --no-backup
#
# Private keys are redacted from the printed output but are included in the
# backup archive (mode 0600) so a restore is complete.
set -euo pipefail

NO_BACKUP=0
[[ "${1:-}" == "--no-backup" ]] && NO_BACKUP=1

if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)"; exit 1; fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK=/var/backups/dishnet/$STAMP
WG_IF=${DISHNET_WG_INTERFACE:-wg0}

section() { printf '\n## %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "# DishNet preflight — $(hostname) — $STAMP"

section "OS"
lsb_release -d 2>/dev/null || cat /etc/os-release | head -2
uname -r; free -m | head -2; df -h / | tail -1

section "WireGuard package / service"
dpkg -l 2>/dev/null | awk '/wireguard|nftables|iptables|ufw|caddy|nginx|apache2|docker|fail2ban/ {print $2, $3}'
systemctl is-enabled "wg-quick@$WG_IF" 2>/dev/null || true
systemctl is-active "wg-quick@$WG_IF" 2>/dev/null || true

section "/etc/wireguard/$WG_IF.conf (keys redacted)"
if [[ -f /etc/wireguard/$WG_IF.conf ]]; then
  sed -E 's/^(\s*(PrivateKey|PresharedKey)\s*=).*/\1 <redacted>/' "/etc/wireguard/$WG_IF.conf"
else
  echo "MISSING: /etc/wireguard/$WG_IF.conf"
fi
ls -l /etc/wireguard/ 2>/dev/null || true

section "wg show (live)"
have wg && wg show "$WG_IF" 2>&1 | sed -E 's/(private key:).*/\1 <redacted>/' || echo "wg not installed"

section "Interfaces and routes"
ip -br addr; echo; ip route

section "Forwarding sysctl"
sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter 2>/dev/null || true
grep -rhE 'ip_forward' /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null || true

section "Firewall: nftables ruleset"
have nft && nft list ruleset 2>/dev/null || echo "nft not installed"

section "Firewall: iptables (legacy/nft shim)"
have iptables-save && iptables-save 2>/dev/null || echo "iptables not installed"
have iptables && iptables -V || true

section "ufw"
have ufw && ufw status verbose || echo "ufw not installed"
grep -E '^DEFAULT_FORWARD_POLICY' /etc/default/ufw 2>/dev/null || true

section "Listening sockets"
ss -lntup

section "SSH daemon (effective)"
sshd -T 2>/dev/null | grep -Ei '^(port|passwordauthentication|permitrootlogin|pubkeyauthentication|allowusers) ' || true

section "Running services"
systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'

section "Existing DishNet installation"
id dishnet 2>/dev/null || echo "user dishnet: absent"
systemctl is-active dishnet-vpnd 2>/dev/null || echo "dishnet-vpnd: not installed"
ls -l /var/lib/dishnet /etc/nftables.d 2>/dev/null || true

section "Checks"
warn() { echo "WARN: $*"; }
ok()   { echo "OK:   $*"; }
if grep -qE 'FORWARD.*-i wg0.*-o wg0.*ACCEPT|iifname "?wg0"? oifname "?wg0"? accept' <(cat "/etc/wireguard/$WG_IF.conf" 2>/dev/null; iptables-save 2>/dev/null; nft list ruleset 2>/dev/null); then
  warn "unrestricted $WG_IF -> $WG_IF forwarding rule present (R1). install.sh --apply removes it from $WG_IF.conf."
else
  ok "no unrestricted $WG_IF -> $WG_IF forwarding rule found"
fi
if grep -qE 'MASQUERADE|masquerade' <(iptables-save 2>/dev/null; nft list ruleset 2>/dev/null); then
  warn "a NAT/masquerade rule exists — check it is not turning the hub into an internet proxy for peers (R2)"
else
  ok "no masquerade rule"
fi
if have ufw && ufw status | grep -q 'Status: active'; then
  warn "ufw is active: its FORWARD policy ($(grep -E '^DEFAULT_FORWARD_POLICY' /etc/default/ufw | cut -d= -f2)) is evaluated alongside dishnet's chain. install.sh adds the required 'ufw route allow' for $WG_IF."
fi
[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] && ok "ip_forward=1" || warn "ip_forward is 0; hub cannot forward between peers"
if ss -lntu | grep -q ':51820 '; then ok "UDP 51820 listening"; else warn "nothing listening on 51820 — is wg-quick@$WG_IF up?"; fi
if [[ -f /etc/wireguard/$WG_IF.conf ]] && grep -q '^\[Peer\]' "/etc/wireguard/$WG_IF.conf"; then
  warn "$WG_IF.conf contains static [Peer] blocks; these will be managed by dishnet-vpnd after migration (they are preserved in the backup)"
else
  ok "no static peers in $WG_IF.conf"
fi

if [[ $NO_BACKUP -eq 0 ]]; then
  section "Backup"
  mkdir -p "$BK"; chmod 700 /var/backups/dishnet "$BK"
  tar czf "$BK/wireguard.tgz" -C / etc/wireguard 2>/dev/null && echo "wrote $BK/wireguard.tgz"
  have nft && nft list ruleset > "$BK/nft-ruleset.txt" 2>/dev/null || true
  have iptables-save && iptables-save > "$BK/iptables-save.txt" 2>/dev/null || true
  have ufw && ufw status verbose > "$BK/ufw-status.txt" 2>/dev/null || true
  ip route > "$BK/ip-route.txt"; ip -br addr > "$BK/ip-addr.txt"
  sysctl -a 2>/dev/null | grep -E 'ip_forward|rp_filter' > "$BK/sysctl.txt" || true
  [[ -f /etc/caddy/Caddyfile ]] && cp /etc/caddy/Caddyfile "$BK/Caddyfile"
  [[ -f /etc/nftables.conf ]] && cp /etc/nftables.conf "$BK/nftables.conf"
  [[ -f /var/lib/dishnet/dishnet.db ]] && sqlite3 /var/lib/dishnet/dishnet.db ".backup '$BK/dishnet.db'" 2>/dev/null || true
  chmod -R go-rwx "$BK"
  echo "backup set: $BK (contains private keys — keep it private)"
  echo "restore with: sudo bash deploy/rollback.sh $BK"
fi
echo
echo "# preflight complete — no configuration was changed"
