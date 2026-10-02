#!/usr/bin/env bash
# Fetches the latest Windows installer from GitHub Releases into the hub's
# installer cache so /get/<code> install links work. Run after each client
# release (or from cron daily). Safe to re-run; atomic replace.
#   sudo bash deploy/fetch-installer.sh            # latest client-v* release
#   sudo bash deploy/fetch-installer.sh client-v0.1.0
set -euo pipefail
DIR=/var/lib/dishnet/installer
TAG=${1:-}
API=https://api.github.com/repos/dishnetafrica/wiregaurd/releases
if [[ -z "$TAG" ]]; then
  TAG=$(curl -fsSL "$API?per_page=50" | grep -oE '"tag_name": *"client-v[0-9.]+"' | head -1 | sed -E 's/.*"(client-v[0-9.]+)"/\1/')
fi
[[ -n "$TAG" ]] || { echo "no client release found"; exit 1; }
URL=$(curl -fsSL "$API/tags/$TAG" | grep -oE '"browser_download_url": *"[^"]+\.exe"' | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')
[[ -n "$URL" ]] || { echo "release $TAG has no .exe asset"; exit 1; }
install -d -o dishnet -g dishnet -m 0750 "$DIR"
curl -fsSL "$URL" -o "$DIR/.download.tmp"
chown dishnet:dishnet "$DIR/.download.tmp"; chmod 0640 "$DIR/.download.tmp"
mv -f "$DIR/.download.tmp" "$DIR/DishNetSecureConnect-Setup.exe"
echo "$TAG" > "$DIR/VERSION"
echo "installed $TAG ($(du -h "$DIR/DishNetSecureConnect-Setup.exe" | cut -f1)) from $URL"
