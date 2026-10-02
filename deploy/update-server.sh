#!/usr/bin/env bash
# Updates dishnet-vpnd on the hub to a given server release (tag vX.Y.Z) or
# the newest server release, then re-runs the installer idempotently.
#   sudo bash deploy/update-server.sh            # newest v* release
#   sudo bash deploy/update-server.sh v0.4.0
# Note: GitHub's "latest" release may be a Windows client build, so this
# script looks for the newest tag that starts with "v".
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "run as root (sudo)"; exit 1; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
API=https://api.github.com/repos/dishnetafrica/wiregaurd/releases
TAG=${1:-}
if [[ -z "$TAG" ]]; then
  TAG=$(curl -fsSL "$API?per_page=50" | grep -oE '"tag_name": *"v[0-9.]+"' | head -1 | sed -E 's/.*"(v[0-9.]+)"/\1/')
fi
[[ -n "$TAG" ]] || { echo "no server release found"; exit 1; }
URL="https://github.com/dishnetafrica/wiregaurd/releases/download/$TAG/dishnet-vpnd-linux-amd64"
curl -fsSL "$URL" -o /root/dishnet-vpnd.new
curl -fsSL "$URL.sha256" | sed 's| .*| /root/dishnet-vpnd.new|' | sha256sum -c --quiet
chmod +x /root/dishnet-vpnd.new && mv -f /root/dishnet-vpnd.new /root/dishnet-vpnd
echo "downloaded $TAG: $(/root/dishnet-vpnd version)"
git -C "$REPO" pull -q || true
export DISHNET_BIN=/root/dishnet-vpnd
: "${DISHNET_DOMAIN:=vpn.dishnetuganda.com}"; export DISHNET_DOMAIN
if ! grep -q '^DISHNET_ADMIN_ALLOW=.' /etc/dishnet/dishnet-vpnd.env 2>/dev/null; then export DISHNET_ALLOW_ANY_ADMIN_IP=yes; fi
bash "$REPO/deploy/install.sh" --apply 2>&1 | grep -E "healthy|loaded|still up|ERROR"
