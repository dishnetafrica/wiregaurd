# Approved decisions (Phase 1 sign-off, 2026-10-02)

These decisions were approved by DishNet after reviewing
`phase1-architecture.md`. They are binding for Phase 2 onwards; change them
here first if they need to change.

## Product

| # | Decision |
|---|---|
| P1 | Product name: **DishNet Secure Connect**. Services, installer and UI never use "WireGuard" as a name; attribution reads "powered by WireGuard®". |
| P2 | Initial target: Windows 10/11 and Windows Server (client and office gateway). |
| P3 | Initial use case: remote access to one authorised office server per customer, particularly Tally and ERP. |
| P4 | Pilot: 3–5 businesses. |
| P5 | Customer experience: install app → enter activation code → Connect. |
| P6 | The office gateway/server **initiates an outbound** WireGuard connection to the hub (Starlink CGNAT). All customer traffic hairpins on the hub. |
| P7 | DNS: `vpn.dishnetuganda.com` (to be confirmed by DishNet; used for HTTPS API + dashboard). |
| P8 | Code signing: unsigned pilot with a clear SmartScreen note in the install guide; sign before broad distribution. |

## Architecture and security

| # | Decision |
|---|---|
| A1 | Backend: Go + SQLite, single binary `dishnet-vpnd`. |
| A2 | Windows client: C#/.NET 8 WPF + official WireGuard embeddable tunnel service (Phase 3, not started until the backend and its security tests are done). |
| A3 | Keep the existing Droplet, WireGuard install, server key, `wg0`, `10.20.0.0/24`, UDP 51820. |
| A4 | No live-server change until backup, preflight audit, migration plan and rollback are ready and reviewed. |
| A5 | The unrestricted `wg0 → wg0` forwarding rule is removed before any customer is onboarded; forwarding is default-deny. |
| A6 | A customer can reach only their own authorised server(s) and the explicitly permitted ports. SMB (445/139) is never in a default template. |
| A7 | Device private keys are generated on the device and never sent to the API. |
| A8 | Activation codes: unique per customer and per role; single-use by default (admin may set a higher `max_uses`); device limit per customer. |
| A9 | `dishnet-vpnd` runs as its own user with `CAP_NET_ADMIN` only; it cannot read the hub private key and executes no client-supplied strings. |
| A10 | Peer provisioning is persisted in SQLite, applied atomically, idempotent and reconciled on boot and periodically. |
| A11 | Address plan: `/28` per customer in the pilot; expandable pools as in `address-plan.md`. |
| A12 | Automated tests cover: cross-tenant access denial, routing/allowed-IPs, revocation, expiry, restart recovery, unauthorised activation and rate limiting. |

## Still to be supplied by DishNet

* Read-only server audit output (`docs/phase1-architecture.md` §7).
* DigitalOcean Cloud Firewall rules and the administrator IP allowlist.
* Confirmation that `/root/wireguard-backup-<date>.tgz` exists (mode 600).
* Confirmation of the DNS name and that DishNet controls its DNS.
