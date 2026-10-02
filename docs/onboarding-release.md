# Guided onboarding release — server v0.6.0 / client 0.4.0

Date: 2026-10-02. Companion to `onboarding-plan.md` (plan), `customer-onboarding-sop.md`, `admin-support-runbook.md`.

## 1. What was delivered

| Part | Delivered | Where |
|---|---|---|
| 1 Windows client onboarding | First-launch welcome + 2-minute animated tour (3 steps, XAML storyboards, reduced-motion via Windows "show animations", captions, keyboard ←/→, Watch later / replay via **How does this work?**); guided checklist with **verified** (activation, registration, handshake, office probe) vs **confirmed** (Remote Desktop, Tally — customer ticks) steps and a "Next:" line; **Open Remote Desktop** (`mstsc /v:<office>`); explicit **Allow Remote Desktop for DishNet users** screen for office PCs (nothing changed until clicked, declinable); plain-language messages; **Contact DishNet support**; support contact from the hub | `windows/src/DishNet.SecureConnect.App/{TourWindow,HelpWindow,MainWindow}.xaml*`, `MainViewModel.cs`, `Core/Onboarding/*` |
| 2 Learning centre | In-app Help window with the ten topics, from one Markdown source | `Core/Onboarding/help-topics.md`, `HelpTopics.cs`, `HelpWindow.xaml` |
| 3 Customer manual | `customer-setup-guide.md` → HTML + PDF (headless Chromium), version/date/support from `docs/manual/config.json`; served at `https://vpn.dishnetuganda.com/guide` and `/guide.pdf`; help topics appended so app and manual never drift | `docs/manual/*`, `tools/build-manual.py`, `server/internal/api/manual.go` |
| 4 Admin dashboard | Per-customer onboarding checklist (telemetry vs entered, next action + owner), office Windows edition, readiness Not checked / Ready / Needs attention, acceptance + handover milestones, support notes (passwords refused), **Support view** with symptom table and failed jobs, progress column on the customer list, manual links | `server/internal/onboarding`, `provision/onboarding.go`, `admin/*`, `store/migrations/0004_onboarding.sql` |
| 5 SOP + runbook | Roles, RACI, stage-by-stage acceptance checks, escalation, handover checklist; support runbook with symptom→cause→action, hub health, recovery | `docs/customer-onboarding-sop.md`, `docs/admin-support-runbook.md` |
| 6 Tests | Client: 61 xunit (checklist never marks unverified steps; consent gating; probe; settings; help content has no internals; update checks; key/config safety). Server: 37 Go (onboarding derivation incl. Windows Home, verified from the office app's report; viewer cannot write; tenant isolation of notes/readiness; manual served without internals; trial, download, update, isolation, revocation, recovery) | `windows/tests`, `server/internal/*/*_test.go` |
| 7 Screenshots | Dashboard, trial page and web guide captured from a seeded dry-run server: `docs/screenshots/`. **Client screenshots are not included** — this environment cannot run WPF; they come from the pilot PC (see §4) | `docs/screenshots/` |

### 1a. Remote Tally journey (server v0.6.0 / client 0.4.0)

| Part | Delivered | Where |
|---|---|---|
| Set up Tally remote access | 8-step guided journey with practice run; verified vs confirmed steps; confirmations accepted only in order; shows the Tally company recorded by DishNet | `Core/Onboarding/TallyJourney.cs`, `App/TallySetupWindow.xaml*` |
| Troubleshooting assistant | Six-layer diagnosis (activation, connection, office PC, Remote Desktop, Windows sign-in, Tally) with owner per layer; observable layers decided automatically, others asked | `Core/Onboarding/Troubleshooter.cs`, `App/TroubleshootWindow.xaml*` |
| Dashboard | Remote Tally pilot checklist (8), acceptance gated on all 8; Tally company; simultaneous-users count + assessment state | `server/internal/onboarding`, `provision/onboarding.go`, `admin/templates/customer.html`, migration `0005_tally.sql` |
| Content | Help topics, manual (v1.1), SOP stage 6, runbook rewritten Tally-first; simultaneous users explained as a separate assessment | `help-topics.md`, `docs/manual/*`, `docs/customer-onboarding-sop.md`, `docs/admin-support-runbook.md` |
| Screenshot | `docs/screenshots/dashboard-tally-readiness.png` (seeded dry-run server) | |

**Success measure:** a non-technical staff member completes all 8 steps of
the journey with minimal help; support records how much help was needed in
the notes. Pilot procedure in §4.

### 1b. DishNet Web Desktop (server v0.7.1)

Tally in the browser: `https://tally.dishnetuganda.com` → sign in → *Open my
office computer* → Windows login of the office PC → desktop in the tab.
Nothing installed on staff devices. Design, security and operations in
`docs/phase5-web-desktop.md`; dashboard *Browser access* card per customer.

## 2. Build instructions

```bash
# server (Linux/macOS/Windows with Go 1.24)
cd server && go test ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dishnet-vpnd ./cmd/dishnet-vpnd
# manual (needs python3 + `pip install markdown`, Chromium for the PDF)
python3 tools/build-manual.py          # regenerates docs/manual/*.html|pdf and server/internal/api/manual/*
# windows client (any OS with .NET 8 SDK for the core; Windows or CI for the installer)
cd windows && dotnet test && dotnet build DishNetSecureConnect.sln
# installer: GitHub → Actions → windows-client → Run workflow → version (publishes client-vX.Y.Z)
# hub: sudo bash deploy/update-server.sh vX.Y.Z && sudo bash deploy/fetch-installer.sh client-vX.Y.Z
```

## 3. Changed files (this feature set)

See `git log --stat 88c899b..HEAD`. Main areas: `windows/src/**` (app, core onboarding, help), `windows/tests`, `server/internal/{onboarding,provision,admin,api,store}`, `docs/manual`, `docs/screenshots`, `docs/*.md`, `tools/build-manual.py`.

## 4. Pilot test procedure (Phase 4, real hardware)

Office PC (Windows Pro) + one staff laptop + a DishNet admin, about 45 minutes:

1. Hub: `update-server.sh v0.6.0`, `fetch-installer.sh client-v0.4.0`. In the dashboard, record the customer's **Tally company** and how many staff need Tally at once. Dashboard → Trial requests → approve a real request (or create a customer) → note both links.
2. Office PC: open the office link → install → the tour appears (screenshot 1) → app connects → **Allow Remote Desktop for DishNet users** appears (screenshot 2) → click Allow → status note reads "Remote Desktop enabled. Firewall allows DishNet users on port 3389." (screenshot 3). Dashboard shows gateway **online**, onboarding row "Office computer online" verified.
3. Staff laptop: open the staff link → install → tour → Connected → checklist: first four steps verified, incl. **Office computer reachable** (screenshot 4). If it says "not answering", stop and diagnose with the Support view.
4. Click **Set up Tally remote access** and let the staff member drive: Open Remote Desktop → sign in → open the named Tally company → one simple task → finish properly (screenshot 5: "Practice run complete"). Support ticks the 8-point pilot checklist in the dashboard as each point is demonstrated. Then click **Something is not working…** once with the office PC switched off to see the assistant name layer 3 (screenshot 5b).
5. Help centre: open **Help**, read "What to do when the connection fails" (screenshot 6); **Contact DishNet support** shows the WhatsApp number.
6. Dashboard: record edition Pro, readiness Ready, acceptance passed, handover done → onboarding "complete" (screenshot 7).
7. Resilience: pull the laptop's internet for 2 minutes → app shows Reconnecting… then Connected without clicks. Switch the office PC off → laptop checklist says "Office computer not answering" within a minute; switch on → reachable again.
8. Revocation: revoke the laptop in the dashboard → app shows "Access revoked" within a minute; Remote Desktop no longer connects.
9. Update: publish client 0.3.2 later → the 0.3.1 app shows the yellow bar → Update now → returns updated, still activated.

Record outcomes in `docs/pilot-test.md` and attach the screenshots to `docs/screenshots/`.

## 5. Assumptions and items needing a human decision

1. **Support contact** is `WhatsApp 0705 993 348`; no email yet. Add `support_email` in `docs/manual/config.json` and `DISHNET_SUPPORT_CONTACT` on the hub when available.
2. **Windows Home office PCs are not supported**; DishNet's answer is "upgrade to Pro, else use another Pro PC". Confirmed by DishNet.
3. **Consent** on the office PC is given in the app by its owner/operator; DishNet support may click it on site only with the owner present (SOP stage 4). Confirmed by DishNet.
4. **One user at a time** on a normal Windows PC via Remote Desktop; simultaneous users need Windows Server + RDS licences — a sales decision per customer.
5. **Tally compatibility is never claimed**; only the acceptance test (customer opens Tally over RDP) sets readiness to Ready.
6. **Mac staff computers** use the manual `activate.sh` flow for now; a Mac app is out of scope.
7. **Client screenshots** must be taken on the pilot PC; the diagrams in the manual are labelled as diagrams, not screenshots.
8. **Notifications** for new trial requests still need a destination (WhatsApp/email via webhook) — open since the trial feature.
9. **Code signing** remains unsigned for the pilot (SmartScreen warning explained in the manual).
