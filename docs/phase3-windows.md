# Phase 3 — Windows client

Status: **app, Windows integration and installer implemented; builds
cross-compiled here, installer produced by CI on `windows-latest`. Not yet
run on a real Windows machine (Phase 4).**

## What exists (`windows/`)

| Project | Target | Purpose |
|---|---|---|
| `src/DishNet.SecureConnect.Core` | net8.0 (cross-platform) | Everything that can be tested without Windows: API client with typed error mapping, WireGuard config renderer with safety checks, X25519 key pairs (BouncyCastle), protected identity store, connection state machine, session orchestration (activate → connect → heartbeat → revoke), log redaction. |
| `tests/DishNet.SecureConnect.Core.Tests` | net8.0 | xunit; runs in CI on Linux. |
| `src/DishNet.SecureConnect.Windows` | net8.0-windows | `DpapiProtector` (machine-scope DPAPI), `WireGuardTunnelController` (official `wireguard.exe /installtunnelservice` integration, status via the tunnel's named pipe), data directory with SYSTEM+Administrators-only ACL, startup registration, redacted diagnostics zip. |
| `src/DishNet.SecureConnect.App` | WPF net8.0-windows | Red/white UI: activation screen, status card (Connected / Connecting / Reconnecting / Access revoked / Problem), Connect / Disconnect, business + device + VPN address + office targets, Start with Windows, Save diagnostics, Reset device. Requires administrator (manifest) — the reason is stated on the activation screen. |
| `installer/` | Inno Setup | `DishNetSecureConnect-Setup-<ver>.exe`: self-contained app + the official signed WireGuard for Windows MSI (installed silently, `DO_NOT_LAUNCH=1`) + third-party notices. Uninstall removes the tunnel service and the device identity. |

Design points already enforced in code:

* The private key is generated on the device (`WireGuardKeys.Generate`) and
  only the public key is sent (`ApiClientTests.Activate_SendsPublicKeyOnly…`).
* `TunnelConfigRenderer` refuses any server-supplied `AllowedIPs` that is not
  a private IPv4 range narrower than /8 — a compromised or buggy backend can
  never turn the client into a full-tunnel VPN.
* Identity (private key, device token) is written only through
  `ISecretProtector`; on Windows that is DPAPI (LocalMachine), so the SYSTEM
  tunnel service and the user's app can both read it but other machines
  cannot. `Delete()` overwrites before unlinking.
* Revocation/suspension/expiry (`403 access_denied`) tears the tunnel down
  and shows "Access revoked"; a network outage does not — the tunnel keeps
  retrying and the UI shows "Reconnecting…".
* `Redactor` strips private keys, device tokens, activation codes and
  passwords from anything destined for logs or the diagnostics bundle.

## Tunnel integration decision

The app drives the tunnel through **WireGuard for Windows' documented
tunnel-service CLI** (`wireguard.exe /installtunnelservice <conf>` /
`/uninstalltunnelservice <name>`), which creates the Windows service
`WireGuardTunnel$DishNetOffice` (auto-start, runs as SYSTEM, reconnects by
itself). This was chosen over the embeddable `tunnel.dll` route for the pilot
because it needs no custom Go build in CI and uses the signed, unmodified
official package; `ITunnelController` isolates the choice so the DLL route can
replace it later without touching the app. The service name prefix
`WireGuardTunnel$` is imposed by the WireGuard tooling and is not shown in
the UI; the display name customers see is DishNet's.

The tunnel configuration (which contains the private key) is written to
`%ProgramData%\DishNet\SecureConnect\DishNetOffice.conf` with an ACL that
grants access only to SYSTEM and Administrators — the same posture as
WireGuard's own configuration store. The identity file is additionally
DPAPI-protected. CI verifies the Authenticode signature of the downloaded
WireGuard MSI (must be valid and issued to WireGuard LLC) before bundling.

## Remaining (in order)

1. ~~`DishNet.SecureConnect.Windows`~~ done (net8.0-windows): `DpapiProtector`;
   `WireGuardTunnelController` that writes the rendered config to
   `%ProgramData%\DishNet\SecureConnect\DishNetOffice.conf.dpapi` and manages
   the tunnel through the official embeddable DLL service (`tunnel.dll` +
   `wireguard.dll` from wireguard-windows, MIT): `WireGuardTunnelService` for
   install/start/stop, status via the WireGuard named pipe.
2. ~~App~~ done   3. ~~Installer~~ done   4. ~~CI~~ done (`.github/workflows/windows.yml`, artifact `DishNetSecureConnect-Setup`)
5. **Phase 4**: run the installer on a real Windows 10/11 machine against the
   live hub; verify activation, Connect, RDP to the office gateway, reconnect
   after a link drop, revocation, reboot, upgrade, uninstall. Fix what breaks.
6. Non-admin helper service (so standard users can Connect without UAC),
   gateway-role switch in the UI (LAN declaration), DishNet logo (placeholder
   icon for now), code signing.

## Licensing (to document in the installer)

`tunnel.dll`, `wireguard.dll` and `wireguard-nt` are MIT-licensed (Jason A.
Donenfeld / WireGuard LLC); redistribution with the licence text is
permitted. "WireGuard" is a registered trademark; the product is "DishNet
Secure Connect, powered by WireGuard®" and never names a service or file
"WireGuard".

## Self-update and gateway auto-setup (client 0.2.3 / server 0.4.0)

* **Updates**: the app asks the hub (`GET /api/v1/client/latest`) at start
  and daily. If the hub carries a newer build (`deploy/fetch-installer.sh`
  after each release), a banner offers **Update now**: the installer is
  downloaded from the hub only (same host, HTTPS), its SHA-256 verified
  against the hub's value, then run with `/SILENT /CLOSEAPPLICATIONS
  /RESTARTAPPLICATIONS`. Identity and the running tunnel service survive;
  nothing is uninstalled. Builds before 0.2.3 do not know how to check, so
  they are upgraded once by running the installer.
* **Office gateway**: on Connect, a gateway-role device enables Remote
  Desktop (`fDenyTSConnections=0`), enables Windows' "Remote Desktop"
  firewall group and adds inbound TCP rules for the ports DishNet policies
  allow, scoped to the VPN range only. The customer does nothing.
