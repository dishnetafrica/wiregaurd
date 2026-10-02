#!/usr/bin/env bash
# DishNet Secure Connect — manual activation helper for the pilot (Linux/macOS).
# Generates a key pair locally, activates against the API and writes a
# wg-quick configuration. The private key never leaves this machine.
#
#   bash tools/activate.sh DN-XXXX-XXXX-XXXX-XXXX "Test laptop"            # client
#   bash tools/activate.sh DN-XXXX-XXXX-XXXX-XXXX "Office server"          # gateway
#   LAN=192.168.10.0/24 bash tools/activate.sh DN-... "Office router"      # gateway + LAN
#
# Requires: wg (wireguard-tools), curl, python3.
set -euo pipefail
CODE=${1:?activation code}; NAME=${2:-$(hostname)}
API=${API:-https://vpn.dishnetuganda.com}
if ! command -v wg >/dev/null; then
  if [[ "$(uname)" == "Darwin" ]] && command -v brew >/dev/null; then
    echo "Installing wireguard-tools with Homebrew (needed once for key generation)..."
    HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1 brew install -q wireguard-tools || true
    command -v wg >/dev/null || { echo "Homebrew could not install wireguard-tools; run: brew install wireguard-tools"; exit 1; }
  else
    echo "wireguard-tools (wg) is not installed. macOS: brew install wireguard-tools   Ubuntu: apt install wireguard-tools"; exit 1
  fi
fi

PRIV=$(wg genkey); PUB=$(echo "$PRIV" | wg pubkey)
BODY=$(python3 - "$CODE" "$PUB" "$NAME" "${LAN:-}" <<'EOF'
import json,sys,platform
code,pub,name,lan=sys.argv[1:5]
b={"code":code,"public_key":pub,"device_name":name,"os":platform.platform(),"client_version":"manual-0.1"}
if lan: b["lan_subnets"]=[x.strip() for x in lan.split(",") if x.strip()]
print(json.dumps(b))
EOF
)
RESP=$(curl -sS -w '\n%{http_code}' -H 'Content-Type: application/json' -d "$BODY" "$API/api/v1/activate")
STATUS=$(echo "$RESP" | tail -1); JSON=$(echo "$RESP" | sed '$d')
if [[ "$STATUS" != "201" ]]; then echo "Activation failed (HTTP $STATUS): $JSON"; exit 1; fi

OUT=$(python3 - "$JSON" "$PRIV" <<'EOF'
import json,sys
r=json.loads(sys.argv[1]); c=r["config"]; priv=sys.argv[2]
allowed=", ".join(c["allowed_ips"])
conf=f"""# DishNet Secure Connect — {c['customer_name']} — {c['device_name']} ({c['role']})
[Interface]
PrivateKey = {priv}
Address = {c['address']}

[Peer]
PublicKey = {c['hub_public_key']}
Endpoint = {c['endpoint']}
AllowedIPs = {allowed}
PersistentKeepalive = {c['persistent_keepalive']}
"""
safe=("dn-"+"".join(ch if ch.isalnum() else "-" for ch in c["device_name"]).strip("-").lower())[:15].rstrip("-")  # wg-quick: interface name <= 15 chars
open(f"{safe}.conf","w").write(conf); open(f"{safe}.token","w").write(r["device_token"])
print(f"Activated: {c['device_name']} as {c['role']} for {c['customer_name']}")
print(f"VPN address : {c['address']}\nAllowed IPs : {allowed or '(none yet — register the gateway first)'}")
for a in c.get("access",[]): print(f"Access      : {a['label']} -> {a['target']} {a['proto']} {','.join(map(str,a['ports']))}")
print(f"\nConfig written: {safe}.conf   (import into the WireGuard app, or: sudo wg-quick up ./{safe}.conf)")
EOF
)
chmod 600 dn-*.conf dn-*.token 2>/dev/null || true
echo "$OUT"
