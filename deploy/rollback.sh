#!/usr/bin/env bash
# DishNet Secure Connect — restore the hub from a preflight backup set.
#
#   sudo bash deploy/rollback.sh /var/backups/dishnet/<stamp>
#
# Restores /etc/wireguard, the nftables config, Caddyfile and (if present)
# the dishnet database, stops dishnet-vpnd and removes its nftables table.
# The WireGuard interface is restarted only if its config actually changed.
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "run as root (sudo)"; exit 1; }
BK=${1:-}
[[ -d "$BK" ]] || { echo "usage: rollback.sh /var/backups/dishnet/<stamp>"; ls -1d /var/backups/dishnet/*/ 2>/dev/null; exit 1; }
WG_IF=${DISHNET_WG_INTERFACE:-wg0}

echo "# rolling back from $BK"
systemctl stop dishnet-vpnd 2>/dev/null || true
systemctl disable dishnet-vpnd 2>/dev/null || true
nft delete table inet dishnet 2>/dev/null && echo "removed nftables table 'dishnet'" || true

if [[ -f "$BK/wireguard.tgz" ]]; then
  before=$(sha256sum "/etc/wireguard/$WG_IF.conf" 2>/dev/null | cut -d' ' -f1 || true)
  tar xzf "$BK/wireguard.tgz" -C /
  after=$(sha256sum "/etc/wireguard/$WG_IF.conf" | cut -d' ' -f1)
  echo "restored /etc/wireguard"
  if [[ "$before" != "$after" ]]; then
    echo "$WG_IF.conf changed; restarting wg-quick@$WG_IF (brief VPN interruption)"
    systemctl restart "wg-quick@$WG_IF"
  fi
fi
[[ -f "$BK/nftables.conf" ]] && install -m 0644 "$BK/nftables.conf" /etc/nftables.conf && echo "restored /etc/nftables.conf"
[[ -f "$BK/nftables.conf.before" ]] && install -m 0644 "$BK/nftables.conf.before" /etc/nftables.conf && echo "restored /etc/nftables.conf (pre-install)"
[[ -f "$BK/Caddyfile.before" ]] && install -m 0644 "$BK/Caddyfile.before" /etc/caddy/Caddyfile && systemctl restart caddy 2>/dev/null && echo "restored Caddyfile"
if [[ -f "$BK/dishnet.db" ]]; then
  install -o dishnet -g dishnet -m 0640 "$BK/dishnet.db" /var/lib/dishnet/dishnet.db
  echo "restored dishnet database (start dishnet-vpnd again to re-provision from it)"
fi
echo "# rollback complete. wg status:"
wg show "$WG_IF" 2>/dev/null | sed -E 's/(private key:).*/\1 <redacted>/' || true
