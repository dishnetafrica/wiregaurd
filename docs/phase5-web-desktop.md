# Phase 5 — DishNet Web Desktop (Tally in the browser)

Date: 2026-10-02 · Status: implemented in server v0.7.0; pilot pending

## Why

The Windows app works, but the daily journey for staff still ends in Windows
Remote Desktop: an address, a credentials dialog, a separate program. For a
non-technical customer that is where it breaks (observed in the pilot on
2026-10-02). The web desktop replaces all of that with one address:

1. Open **https://tally.dishnetuganda.com** in any browser (Windows, Mac,
   Chromebook, tablet).
2. Sign in with the DishNet login (plus a 6-digit code from an authenticator
   app if the user switched that on).
3. Click **Open my office computer**, type the office PC's Windows user name
   and password once, and the office desktop with Tally appears in the tab.

Nothing is installed on staff devices and no activation codes are needed for
them. The office PC is unchanged: it runs the DishNet app with Remote Desktop
allowed, exactly as today.

## How it works

```
browser ──HTTPS/WebSocket──▶ Caddy ──▶ dishnet-vpnd (/desk)
                                           │  Guacamole protocol (loopback)
                                           ▼
                                        guacd (Ubuntu package, 127.0.0.1:4822)
                                           │  RDP, source 10.20.0.1
                                           ▼ wg0 (existing tunnel)
                                   office PC 10.20.0.x:3389
```

- **guacd** is Apache Guacamole's small C engine (`apt install guacd`, ~30 MB
  per session). The Java web application that normally fronts it is *not*
  used: the hub has 458 MB of RAM, and we want user management, tenant
  isolation and audit inside dishnet-vpnd where they already live.
- **dishnet-vpnd** serves the pages under `/desk`, holds the sign-in session,
  and bridges the browser's WebSocket to guacd using the Apache
  `guacamole-common-js` client (Apache-2.0, vendored in
  `server/internal/desk/static`).
- **The browser never names a target.** On connect, the hub looks up the
  signed-in user's customer and that customer's active office computer with
  an enabled any-client Remote Desktop policy. A user of one customer cannot
  reach another's office under any input.
- **Windows credentials** are typed per session, held in memory for at most
  90 seconds inside a one-time ticket, passed to guacd for that session only,
  and never written to the database, logs or audit. The audit records who
  connected to which office computer, when, from which IP, and the outcome.
- **Routes and firewall.** Gateway tunnels now also route the hub's address
  (`10.20.0.1/32`) so the office PC accepts the hub's connections; the office
  firewall rule already allows the whole VPN range. The hub's nftables input
  chain accepts replies to connections the hub opened; nothing else changes.
  RDP remains unreachable from the internet.

## Accounts and security

| Control | Detail |
|---|---|
| Web users | Created per customer in the dashboard (*Browser access* card). Login 3–40 chars; temporary password shown once; must be changed at first sign-in; minimum 10 characters |
| Two-factor | Optional per user, TOTP (RFC 6238) with any authenticator app; QR enrolment on the user's *Security* page; admins can clear it (lost phone), which signs the user out |
| Sessions | 12 h cookie, HttpOnly, Secure, SameSite=Strict, scoped to `/desk`; CSRF token on every form |
| Rate limits | 10 sign-in attempts per 15 min per IP *and* per login; same for 2FA codes |
| Switch-off | *Browser access off* on the customer page signs every user of that customer out immediately; disabling a user does the same for that user |
| Subscription | Expired or suspended customers cannot sign in (same rules as the apps) |
| Headers | CSP `default-src 'none'` with self-only scripts, no framing, no referrer |

Trade-off to state plainly to customers: with the web desktop the hub (a
DishNet-controlled server) terminates the Remote Desktop session and
re-encrypts it to the browser. With the Windows app the screen traffic is
end-to-end between laptop and office PC. Both are encrypted in transit; the
web path trusts DishNet's hub additionally.

## Operating it

- Enable per customer: customer page → *Browser access* → **Switch on**; add
  users; give each person their login and temporary password by a private
  channel. Never ask for or note their Windows password.
- Support: *Audit log* shows `webuser.login`, `webuser.login_failed`,
  `webdesk.connect` (with outcome: session started / guacd unreachable /
  handshake failed). `systemctl status guacd` on the hub.
- Hub settings: `DISHNET_DESK_URL` (default `https://tally.dishnetuganda.com`)
  and `DISHNET_GUACD` (default `127.0.0.1:4822`) in
  `/etc/dishnet/dishnet-vpnd.env`; `DISHNET_DESK_DOMAIN` for
  `deploy/install.sh` to add the Caddy site.
- DNS: `tally.dishnetuganda.com` A record → 165.227.89.92 before deploying,
  so Caddy can obtain the certificate.
- Rollback: `update-server.sh v0.6.2`; the `0007` tables stay unused.
  `systemctl disable --now guacd` if the engine should go too.

## Limits

- One interactive user per standard Windows Pro PC (Windows rule; same as
  the app). Several at once still needs the Windows Server / RDS assessment.
- No printing or file transfer between the browser device and the office PC
  in this version (the Windows app's Remote Desktop can do both).
- Audio is off (not needed for Tally; saves bandwidth).
- Tested in this environment with a protocol-faithful fake guacd (handshake,
  parameters, one-time tickets, isolation, 2FA). The real guacd/RDP path is
  verified in the pilot: see the checklist in `docs/pilot-test.md`.
