# Pilot test — first two devices through the live hub

Uses the official WireGuard client and the helper scripts in `tools/` until
the DishNet Windows app (Phase 3) exists. Nothing here touches the hub by
hand; everything goes through the dashboard and the API.

## 0. In the dashboard (https://vpn.dishnetuganda.com/admin)

1. Customers → New customer: name `DishNet Test`, device limit 5, default
   ports `3389` (add `,9000` if you will test Tally directly). Create.
2. On the customer page: Generate code, role **Office gateway / server** →
   note the code (shown once).
3. Generate code, role **Client** → note the code.

## 1. Office server (Windows PC/Server that hosts Tally/RDP) — the GATEWAY

1. Install WireGuard for Windows: https://www.wireguard.com/install/
2. Download `tools/activate.ps1` from the repository. In an **Administrator**
   PowerShell:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\activate.ps1 -Code DN-GATEWAY-CODE -Name "Office server"
   ```
   Expected: `Activated: Office server as gateway for DishNet Test`,
   `VPN address : 10.20.0.17/32`, `Allowed IPs : 10.20.0.16/28`, and a file
   `DishNet-Office-server.conf` on the Desktop.
3. WireGuard → Add Tunnel → Import tunnel(s) from file → select it → **Activate**.
   Within ~30 s the tunnel shows *Latest handshake: … seconds ago*.
4. **Windows Firewall** — WireGuard's adapter is usually classed as a
   *Public* network, where Remote Desktop is blocked by default. Allow RDP
   from the VPN only (Administrator PowerShell):
   ```powershell
   Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
   New-NetFirewallRule -DisplayName "DishNet VPN - RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.20.0.0/24 -Action Allow -Profile Any
   ```
   and make sure Remote Desktop is enabled (Settings → System → Remote Desktop).
   For Tally over its own port add the same rule with `-LocalPort 9000`.

## 2. Staff laptop (Windows 10/11) — the CLIENT

1. Install WireGuard for Windows.
2. Administrator PowerShell:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\activate.ps1 -Code DN-CLIENT-CODE -Name "Test laptop"
   ```
   Expected: `VPN address : 10.20.0.18/32`, `Allowed IPs : 10.20.0.17/32`,
   `Access : default Office server -> 10.20.0.17 tcp 3389`.
3. Import and Activate the tunnel.
4. Open **Remote Desktop Connection** to `10.20.0.17` → the office server's
   login screen appears. That is the product working end to end.

## 3. Verify isolation and revocation (on the hub, read-only)

```bash
wg show wg0 | grep -E 'peer|allowed|handshake'
#   two peers, allowed ips 10.20.0.17/32 and 10.20.0.18/32, both with recent handshakes
nft list chain inet dishnet vpn_from_peer
#   one accept rule: ip saddr 10.20.0.18 ip daddr 10.20.0.17 tcp dport { 3389 } accept
#   the final "dishnet default deny" counter rises if the laptop tries anything else
```

From the laptop: `ping 10.20.0.17` → times out (ICMP not in policy —
expected); `ping 10.20.0.1` → replies (hub allows ping to itself);
anything outside `10.20.0.17` is not even routed into the tunnel.

Then in the dashboard revoke **Test laptop** → `wg show` loses the peer
within a second, the laptop's handshake stops, and in the dashboard the
device shows *revoked*. A second laptop can only join with a new code.

## 4. Things to expect

* **Starlink CGNAT**: the office server dials out; it must stay connected
  for clients to reach it. `PersistentKeepalive = 25` keeps the NAT mapping
  alive. If the office server reboots, WireGuard for Windows reconnects the
  tunnel automatically if it was active at shutdown.
* **Addresses**: the gateway always gets the first address of the customer's
  block (`.17` in block `10.20.0.16/28`), clients follow.
* **No gateway yet?** A client activated before its gateway gets an empty
  `AllowedIPs`; re-run `activate.ps1`? No — simply wait: the next Phase 3
  client refreshes config automatically. For the manual pilot, register the
  gateway first.
* The dashboard's *Online* column updates every 60 s from the hub's
  handshake data.
