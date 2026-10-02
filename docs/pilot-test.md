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
   `dn-office-serve.conf` on the Desktop.
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

## 5. Trying it from a Mac first (no office gateway needed)

1. Install **WireGuard** from the Mac App Store (free, by WireGuard Development Team).
2. In Terminal (Homebrew required — https://brew.sh — the script installs `wireguard-tools` itself):
   ```bash
   curl -fsSLO https://raw.githubusercontent.com/dishnetafrica/wiregaurd/claude/epic-ramanujan-wkwq3j/tools/activate.sh
   bash activate.sh DN-YOUR-CLIENT-CODE "Bhavin MacBook"
   ```
   Expected: `Activated: Bhavin MacBook as client for DishNet Test`,
   `VPN address : 10.20.0.17/32`, `Allowed IPs : 10.20.0.1/32` (plus the
   office gateway once one is registered), and `dn-bhavin-macbo.conf` (tunnel names are limited to 15 characters)
   in the current folder.
3. Open the WireGuard app → **Import tunnel(s) from file** → choose the
   `.conf` → **Activate**. Within seconds the app shows a handshake and the
   dashboard shows the device *online*.
4. Connectivity check: `ping 10.20.0.1` replies. Anything else (e.g.
   `ping 10.20.0.2`, `curl http://10.20.0.1`) is refused — that is the
   default-deny policy working. On the hub, `wg show wg0` lists your key.
5. Revoke the device in the dashboard → the handshake stops within a minute
   and `ping 10.20.0.1` fails. Re-activating needs a new code.

The Mac can only be a *client* in this pilot (the office gateway role is
for the Windows machine that hosts Tally/RDP). To test the real use case,
continue with §1–§2 on the office PC; the Mac then reaches it over RDP via
Microsoft Remote Desktop from the App Store.

## Results log

| Date | Test | Result |
|---|---|---|
| 2026-10-02 | Hub deployed (v0.1.0 → v0.1.1), TLS issued, dashboard login, customer `DishNet Test` created, codes generated | ✔ |
| 2026-10-02 | macOS client (Intel MacBook, wireguard-tools + wg-quick): activation via API → `10.20.0.17/32`, `AllowedIPs 10.20.0.1/32`; tunnel up; `ping 10.20.0.1` 3/3 replies (~300 ms); `ping 10.20.0.2` denied | ✔ first end-to-end tunnel |
| 2026-10-02 | Hub updated to server v0.5.1 (`dishnet-vpnd a6e943d`), installer cache client-v0.3.1; `/api/v1/client/latest` = 0.3.1 / sha256 `376bdc9c…a51aff` / 55,803,150 bytes; `/guide` HTTP 200; wg0 untouched | ✔ verified from hub output |
| 2026-10-02 | Hub updated to server v0.6.0 (`dishnet-vpnd 998ce23`), installer cache client-v0.4.0; `/api/v1/client/latest` = 0.4.0 / sha256 `c675ac1a…58bb4` / 55,819,608 bytes | ✔ verified from hub output |
| 2026-10-02 | Office PC KISHAN on 0.3.1 (screenshot): in-place update kept activation + paid plan (to 31 Oct 2028); owner clicked Allow (RDP enabled, firewall 3389 only); device #6 at 10.20.0.69. **Tunnel stuck at "Waiting for handshake"** — hub-side peer / UDP check pending | ✖ open |
| 2026-10-02 | Dashboard shows KISHAN registered 5× (10.20.0.65–.69; 2× 0.2.1, 2× 0.2.3, 1× 0.3.1) with 3 duplicate default policies; gateway code 5/5 used. Cause: uninstall deleted identity → reinstall from link re-activated. Fixed in server v0.6.1 (same-name gateway re-activation replaces the old record; revoke deletes its policies) and client 0.4.1 (uninstall keeps identity) | ✔ root-caused, fixed |
| — | Office PC KISHAN: Update now to 0.4.x; edition reported to dashboard; stays Connected | pending |
| — | Office gateway (Windows) + RDP from client | pending |
| — | Revocation observed on a live tunnel | pending |

## 6. Install link flow (no code typing) — from server v0.2.0 / client v0.2.0

1. Dashboard → customer → Generate code (role Client, max uses = number of
   PCs). The one-time reveal shows the code **and** an install link
   `https://vpn.dishnetuganda.com/get/DN-….` Send the link to the customer.
2. Customer opens the link → browser downloads
   `DishNetSecureConnect-Setup-DN-….exe` → runs it (SmartScreen *More info →
   Run anyway*, UAC *Yes*) → the app opens, activates with the code from the
   file name and connects. "Start with Windows" is switched on.
3. The status card shows *Free trial — N days left*. New customers are 30-day
   trials by default; on the customer page: **Extend 30 days**, **Mark paid**
   (+30 days / +1 year), or **Suspend**. When the date passes all devices are
   cut off within a minute and the app shows *Free trial has ended*;
   extending reconnects them within a minute.

Hub prerequisite: the installer must be cached on the hub —
`sudo bash deploy/fetch-installer.sh` after every client release (it pulls
the latest `client-v*` GitHub Release into `/var/lib/dishnet/installer/`).
| 2026-10-02 | Windows 10/11 PC, installer 0.2.0 (direct download, no code in name): install OK incl. WireGuard component; post-install launch failed `CreateProcess failed; code 740` (Inno de-elevates post-install Run items; app requires admin) | ✘ fixed in 0.2.1 (`runascurrentuser`) |
| 2026-10-02 | Windows PC, client 0.2.1 via trial-request → Approve → gateway install link: app launched, auto-activated (customer "Kishan Bhai", device KISHAN gateway 10.20.0.65), trial countdown shown; Connect failed `Attempted to perform an unauthorized operation` (SetAccessControl on an open FileStream lacks WRITE_DAC) | ✘ fixed in 0.2.2 (ACL via FileInfo, non-fatal) |
