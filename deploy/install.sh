#!/usr/bin/env bash
# DishNet Secure Connect — hub installer / upgrader.
#
#   sudo bash deploy/install.sh                 # DRY RUN: prints every change it would make
#   sudo bash deploy/install.sh --apply         # performs the changes
#
# Required environment (export before running --apply):
#   DISHNET_DOMAIN       e.g. vpn.dishnetuganda.com  (for Caddy / Let's Encrypt)
#   DISHNET_ADMIN_ALLOW  comma-separated admin IPs/CIDRs allowed to open /admin (strongly recommended)
# Optional:
#   DISHNET_WG_INTERFACE (wg0)   DISHNET_WG_ENDPOINT (165.227.89.92:51820)
#   DISHNET_BIN          path to a pre-built dishnet-vpnd binary (else built with local Go toolchain)
#
# Invariants (never changed by this script): the WireGuard private key, the
# interface address/subnet, the listen port, sshd configuration, the
# DigitalOcean cloud firewall. Every file it replaces is first copied to the
# preflight backup directory it creates.
set -euo pipefail

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1
[[ $EUID -ne 0 ]] && { echo "run as root (sudo)"; exit 1; }

REPO=$(cd "$(dirname "$0")/.." && pwd)
WG_IF=${DISHNET_WG_INTERFACE:-wg0}
DOMAIN=${DISHNET_DOMAIN:-}
ADMIN_ALLOW=${DISHNET_ADMIN_ALLOW:-}
ENDPOINT=${DISHNET_WG_ENDPOINT:-165.227.89.92:51820}
BIN_SRC=${DISHNET_BIN:-}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK=/var/backups/dishnet/$STAMP

say()  { printf '%s\n' "$*"; }
plan() { printf '  [plan] %s\n' "$*"; }
run()  { if [[ $APPLY -eq 1 ]]; then printf '  [do]   %s\n' "$*"; "$@"; else plan "$*"; fi; }

say "# DishNet hub install — $(hostname) — $STAMP — mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)"

# ---------- 0. preconditions ----------
[[ -f /etc/wireguard/$WG_IF.conf ]] || { say "ERROR: /etc/wireguard/$WG_IF.conf not found; refusing (this script does not create the hub)"; exit 1; }
if [[ $APPLY -eq 1 && -z "$DOMAIN" ]]; then say "ERROR: DISHNET_DOMAIN is required for --apply (TLS)"; exit 1; fi
if [[ -n "$BIN_SRC" && ! -x "$BIN_SRC" ]]; then
  say "ERROR: DISHNET_BIN=$BIN_SRC does not exist or is not executable. Download it first:"
  say "  curl -fL https://github.com/dishnetafrica/wiregaurd/releases/latest/download/dishnet-vpnd-linux-amd64 -o $BIN_SRC && chmod +x $BIN_SRC"
  exit 1
fi
if [[ -z "$ADMIN_ALLOW" ]]; then
  if [[ "${DISHNET_ALLOW_ANY_ADMIN_IP:-}" == "yes" ]]; then
    say "WARNING: DISHNET_ADMIN_ALLOW empty — the dashboard accepts logins from ANY address (password + rate limit only). Set an allowlist in /etc/dishnet/dishnet-vpnd.env before onboarding paying customers."
  else
    say "ERROR: DISHNET_ADMIN_ALLOW is empty. Either set it (comma-separated IPs/CIDRs) or export DISHNET_ALLOW_ANY_ADMIN_IP=yes to accept the risk during testing."; exit 1
  fi
fi

# ---------- 1. backup ----------
say "## 1. Backup"
if [[ $APPLY -eq 1 ]]; then bash "$REPO/deploy/preflight.sh" > "/tmp/dishnet-preflight-$STAMP.txt" 2>&1 || true; BK=$(ls -d /var/backups/dishnet/*/ | sort | tail -1); BK=${BK%/}; say "  backup at $BK"; else plan "bash deploy/preflight.sh  (creates /var/backups/dishnet/<stamp>/)"; fi

# ---------- 2. packages ----------
say "## 2. Packages (nftables, caddy, sqlite3)"
need=()
for p in nftables sqlite3; do dpkg -s "$p" >/dev/null 2>&1 || need+=("$p"); done
if ! command -v caddy >/dev/null; then need+=(caddy); fi
if [[ ${#need[@]} -gt 0 ]]; then
  if printf '%s\n' "${need[@]}" | grep -q caddy && ! apt-cache show caddy >/dev/null 2>&1; then
    run bash -c "apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list && apt-get update"
  fi
  run apt-get install -y "${need[@]}"
else
  say "  all present"
fi

# ---------- 3. service user, directories ----------
say "## 3. Service user and directories"
id dishnet >/dev/null 2>&1 || run useradd --system --home /var/lib/dishnet --shell /usr/sbin/nologin dishnet
run install -d -o dishnet -g dishnet -m 0750 /var/lib/dishnet
run install -d -o root -g dishnet -m 0775 /etc/nftables.d
run install -d -m 0755 /etc/dishnet

# ---------- 4. binary ----------
say "## 4. Binary"
if [[ -n "$BIN_SRC" ]]; then
  run install -m 0755 "$BIN_SRC" /usr/local/bin/dishnet-vpnd.new
elif command -v go >/dev/null; then
  if [[ $(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo) -lt 1500 && $(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo) -lt 1000 ]]; then
    say "ERROR: building on this host needs ~1.5 GB RAM or swap. Download the CI artifact instead and set DISHNET_BIN (see docs/phase2-backend.md §4)."; [[ $APPLY -eq 1 ]] && exit 1
  fi
  run bash -c "cd '$REPO/server' && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.version=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo manual)' -o /usr/local/bin/dishnet-vpnd.new ./cmd/dishnet-vpnd"
else
  say "ERROR: no Go toolchain and DISHNET_BIN not set. Build on another machine: cd server && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dishnet-vpnd ./cmd/dishnet-vpnd"; [[ $APPLY -eq 1 ]] && exit 1
fi
run bash -c "mv -f /usr/local/bin/dishnet-vpnd.new /usr/local/bin/dishnet-vpnd"

# ---------- 5. nftables include ----------
say "## 5. nftables (persistent include of the generated dishnet table)"
if [[ ! -f /etc/nftables.conf ]] || ! grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf; then
  [[ -f /etc/nftables.conf && $APPLY -eq 1 ]] && cp /etc/nftables.conf "$BK/nftables.conf.before"
  if [[ ! -f /etc/nftables.conf ]]; then
    run bash -c "printf '#!/usr/sbin/nft -f\ninclude \"/etc/nftables.d/*.nft\"\n' > /etc/nftables.conf"
  else
    run bash -c "printf '\ninclude \"/etc/nftables.d/*.nft\"\n' >> /etc/nftables.conf"
  fi
fi
# A valid placeholder so `nft -f /etc/nftables.conf` works before the service runs.
[[ -f /etc/nftables.d/dishnet.nft ]] || run install -o root -g dishnet -m 0664 "$REPO/deploy/nftables/dishnet-empty.nft" /etc/nftables.d/dishnet.nft
run systemctl enable nftables.service
# Caution: do NOT `systemctl restart nftables` here on a host that uses ufw/iptables;
# `nft -f` of our file alone is enough and is done by the service at start.

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
  say "  ufw is active: allowing routed traffic on $WG_IF so dishnet's own default-deny chain decides"
  run ufw route allow in on "$WG_IF" out on "$WG_IF"
  run ufw allow 51820/udp
  run ufw allow 443/tcp
fi

# ---------- 6. wg0.conf migration: remove the broad forwarding rule ----------
say "## 6. $WG_IF.conf — strip PostUp/PostDown forwarding rules (R1/R4)"
if grep -qE '^\s*(PostUp|PostDown|PreUp|PreDown)' "/etc/wireguard/$WG_IF.conf"; then
  say "  lines that will be removed:"; grep -nE '^\s*(PostUp|PostDown|PreUp|PreDown)' "/etc/wireguard/$WG_IF.conf" | sed 's/^/    /'
  if [[ $APPLY -eq 1 ]]; then
    cp "/etc/wireguard/$WG_IF.conf" "$BK/$WG_IF.conf.before"
    sed -i -E '/^\s*(PostUp|PostDown|PreUp|PreDown)/d' "/etc/wireguard/$WG_IF.conf"
    say "  removed. The rules stay active in the kernel until the next 'wg-quick down/up'; the dishnet default-deny chain already overrides them."
    say "  (Optional, causes ~2s of VPN downtime) flush the stale kernel rule now:"
    say "     iptables -D FORWARD -i $WG_IF -o $WG_IF -j ACCEPT 2>/dev/null; iptables -D FORWARD -i $WG_IF -j ACCEPT 2>/dev/null"
  fi
else
  say "  none present"
fi
if grep -q '^\[Peer\]' "/etc/wireguard/$WG_IF.conf"; then
  say "  NOTE: static [Peer] blocks found; dishnet-vpnd will REMOVE unknown peers on its first reconcile. Import them as devices first or delete the blocks after backup."
fi

# ---------- 7. systemd unit + environment ----------
say "## 7. dishnet-vpnd service"
if [[ ! -f /etc/dishnet/dishnet-vpnd.env ]]; then
  run bash -c "cat > /etc/dishnet/dishnet-vpnd.env <<EOF
DISHNET_DB=/var/lib/dishnet/dishnet.db
DISHNET_LISTEN=127.0.0.1:8080
DISHNET_WG_INTERFACE=$WG_IF
DISHNET_WG_ENDPOINT=$ENDPOINT
DISHNET_POOL=10.20.0.0/24
DISHNET_POOL_BLOCK=28
DISHNET_HUB_ADDRS=10.20.0.1
DISHNET_NFT_FILE=/etc/nftables.d/dishnet.nft
DISHNET_ADMIN_ALLOW=$ADMIN_ALLOW
DISHNET_TRUST_PROXY=true
DISHNET_RECONCILE=60s
EOF
chmod 0640 /etc/dishnet/dishnet-vpnd.env; chgrp dishnet /etc/dishnet/dishnet-vpnd.env"
else
  say "  /etc/dishnet/dishnet-vpnd.env exists — left unchanged"
fi
run install -m 0644 "$REPO/deploy/systemd/dishnet-vpnd.service" /etc/systemd/system/dishnet-vpnd.service
run systemctl daemon-reload
run systemctl enable dishnet-vpnd

# ---------- 8. Caddy ----------
say "## 8. Caddy (TLS for $DOMAIN -> 127.0.0.1:8080)"
if [[ $APPLY -eq 1 ]]; then
  [[ -f /etc/caddy/Caddyfile ]] && cp /etc/caddy/Caddyfile "$BK/Caddyfile.before"
  sed "s/__DOMAIN__/$DOMAIN/" "$REPO/deploy/caddy/Caddyfile" > /etc/caddy/Caddyfile
  caddy validate --config /etc/caddy/Caddyfile >/dev/null
  systemctl enable caddy; systemctl restart caddy
else
  plan "write /etc/caddy/Caddyfile for ${DOMAIN:-<DISHNET_DOMAIN>} and restart caddy"
fi

# ---------- 9. start + validate ----------
say "## 9. Start and validate"
if [[ $APPLY -eq 1 ]]; then
  systemctl restart dishnet-vpnd
  sleep 2
  systemctl is-active dishnet-vpnd >/dev/null || { journalctl -u dishnet-vpnd -n 30 --no-pager; say "ERROR: service failed; run deploy/rollback.sh $BK"; exit 1; }
  curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null && say "  API healthy"
  nft list table inet dishnet >/dev/null && say "  nftables table 'dishnet' loaded"
  wg show "$WG_IF" >/dev/null && say "  $WG_IF still up (key/port untouched)"
  say
  say "Next: create the first administrator:"
  say "  sudo -u dishnet DISHNET_DB=/var/lib/dishnet/dishnet.db dishnet-vpnd admin-create you@dishnet.example owner"
  say "Then open https://$DOMAIN/admin"
else
  plan "systemctl restart dishnet-vpnd && curl http://127.0.0.1:8080/api/v1/health"
  say
  say "Dry run complete. Nothing was changed. Re-run with --apply to perform the steps above."
fi
