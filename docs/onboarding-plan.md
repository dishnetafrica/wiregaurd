# Guided onboarding, help centre, manuals and admin checklist — plan

Date: 2026-10-02. Branch `claude/epic-ramanujan-wkwq3j`. Hub: server v0.4.0, client 0.2.3.

## 1. What exists today (inspected)

| Area | State | Gap against the brief |
|---|---|---|
| Windows client (`windows/src/DishNet.SecureConnect.App`) | One window: activation screen, status card (Connected / Connecting / Reconnecting / Access revoked / Problem), Connect/Disconnect, business/device/VPN address/office access, trial countdown, Start with Windows, Save diagnostics, Reset, update banner | **No welcome/tour, no checklist, no help centre, no "open Remote Desktop" action, no troubleshooting text, no support contact shown** |
| Office-gateway setup (`WindowsGatewaySetup`, 0.2.3) | Enables Remote Desktop + adds VPN-scoped firewall rules **automatically on Connect** | **Violates the brief's consent rule** — must become an explicit, explained "Allow" step |
| Reachability | State "Connected" is derived from the WireGuard handshake only | **No probe of the office computer's RDP port**; must not claim Tally reachable from a handshake |
| Support contact | `DISHNET_SUPPORT_CONTACT` on the hub, shown on the public trial/download pages only | Not delivered to the app; manuals have no central source |
| Server API (`/api/v1/*`) | activate, config, heartbeat, rotate-key, client/latest, downloads, trial form | Device config lacks `support_contact`; no onboarding/readiness records |
| Dashboard (`server/internal/admin`) | Customers, codes, devices (online/handshake/traffic), policies, plan/trial, trial requests, jobs, audit, admins, roles owner/operator/viewer, CSRF, allowlist | **No onboarding checklist, readiness status, support notes, next-action/owner, manual link** |
| Docs | Architecture, decisions, runbook, pilot test, Phase docs | **No customer manual, no SOP, no support runbook** |
| Tests | Server 33 Go tests; client 48 xunit tests (core only; WPF UI untested) | New logic must be covered: checklist derivation, consent gating, probe, readiness, permissions |
| Tooling here | Go, .NET 8/10 SDK (WPF cross-compiles), headless Chromium (HTML → PDF), no Windows desktop | Client screenshots must come from the pilot PC (or CI); dashboard screenshots can be taken here |

Verified working on real hardware so far: install → trial-request → approve → install link → auto-activation → trial countdown (Windows PC "KISHAN", gateway role). **Not yet verified:** Connect on 0.2.3, gateway reachability, RDP into the office PC, Tally use.

## 2. Phases (each small, tested, pushed; nothing touches the live hub or customer records until a release is explicitly applied)

| Phase | Deliverable | Tests |
|---|---|---|
| **A. Foundations** (contract + logic, no UI) | `support_contact` in device config from the hub's single setting; **explicit consent** gate for gateway setup (persisted locally, explained); **reachability probe** (TCP connect to the office computer's allowed port over the tunnel); **checklist model** with verified vs. user-confirmed steps; local user settings store (tour seen, consent, manual confirmations) | xunit: checklist derivation never marks unverified steps; consent gating; probe result mapping; settings round-trip. Go: config carries support contact |
| **B. Client onboarding UI** | Welcome screen (first launch), 2-minute tour with three animated steps (XAML storyboards, reduced-motion aware, captions, keyboard), guided checklist with live state, "Open Remote Desktop" (launches `mstsc /v:<office>`), plain-language troubleshooting, Contact support, "How does this work?" secondary action, Replay tutorial | core logic tested; UI compiled on CI; manual pilot run |
| **C. Help centre** | In-app Help window with the ten topics in plain English; same content generated from one Markdown source used by the manual | content snapshot test (topics present) |
| **D. Customer manual** | `docs/manual/customer-setup-guide.md` → HTML + PDF via headless Chromium (`tools/build-manual.sh`), served by the hub at `/guide` and `/guide.pdf`; version/date and support contact from one config | Go test: `/guide` served, no secrets |
| **E. Admin onboarding & support views** | Per-customer onboarding checklist (telemetry-derived vs admin-entered), readiness (Not checked / Ready / Needs attention), support notes + last activity, next action + owner, manual/onboarding links; customers list progress column; support diagnosis view | Go: stage derivation, tenant isolation, viewer cannot write notes |
| **F. SOP + runbook** | `docs/customer-onboarding-sop.md`, `docs/admin-support-runbook.md` with RACI, acceptance checks, escalation, handover checklist | review |
| **G. Release + pilot** | server vNext + client 0.3.0; screenshots (dashboard here; client from pilot PC); pilot procedure | — |

## 3. Assumptions / decisions needed from DishNet

1. Support contact: a single phone/WhatsApp and email (currently placeholder "WhatsApp 0705 993 348").
2. Remote Desktop client: Windows' built-in `mstsc` on Windows; Microsoft Remote Desktop app on macOS. No third-party RDP.
3. Windows Home on the office computer is **not supported** as a gateway (cannot accept RDP); the manual says so and the dashboard flags it. Alternative arrangements (upgrade to Pro, or a different PC) are a sales conversation, not a technical workaround.
4. Tally compatibility is only ever confirmed by the customer opening Tally over RDP during the acceptance test — the product never claims it.
5. Consent for enabling Remote Desktop/firewall is given in the app by whoever operates the office PC (customer or DishNet support on site); the dashboard records that it was given, with timestamp, as customer-entered information.
