# Phase 3 — Windows client

Status: **core library implemented and tested (33 tests); WPF app, Windows
service integration and installer not started.**

## What exists (`windows/`)

| Project | Target | Purpose |
|---|---|---|
| `src/DishNet.SecureConnect.Core` | net8.0 (cross-platform) | Everything that can be tested without Windows: API client with typed error mapping, WireGuard config renderer with safety checks, X25519 key pairs (BouncyCastle), protected identity store, connection state machine, session orchestration (activate → connect → heartbeat → revoke), log redaction. |
| `tests/DishNet.SecureConnect.Core.Tests` | net8.0 | xunit; runs in CI on Linux. |

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

## Next (in order)

1. **`DishNet.SecureConnect.Windows`** (net8.0-windows): `DpapiProtector`;
   `WireGuardTunnelController` that writes the rendered config to
   `%ProgramData%\DishNet\SecureConnect\DishNetOffice.conf.dpapi` and manages
   the tunnel through the official embeddable DLL service (`tunnel.dll` +
   `wireguard.dll` from wireguard-windows, MIT): `WireGuardTunnelService` for
   install/start/stop, status via the WireGuard named pipe.
2. **`DishNet.SecureConnect.App`** (WPF, net8.0-windows): red/white UI —
   activation screen, Connect/Disconnect, state + office server address,
   "Start with Windows", "Send diagnostics" (zip, redacted). Binds to
   `SessionManager`; a 60-second timer calls `HeartbeatAsync`.
3. **Installer** (Inno Setup): bundles the app, `tunnel.dll`, `wireguard.dll`
   and the WireGuard licence/attribution; requests elevation once (UAC text
   explains why); upgrade and uninstall remove the tunnel service.
4. **CI**: `windows-latest` job builds the app and installer artifact.
5. Phase 4 integration test on two Windows machines through the live hub.

## Licensing (to document in the installer)

`tunnel.dll`, `wireguard.dll` and `wireguard-nt` are MIT-licensed (Jason A.
Donenfeld / WireGuard LLC); redistribution with the licence text is
permitted. "WireGuard" is a registered trademark; the product is "DishNet
Secure Connect, powered by WireGuard®" and never names a service or file
"WireGuard".
