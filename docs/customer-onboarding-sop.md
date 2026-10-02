# DishNet Secure Connect — Customer onboarding SOP

Version 1.0 · 2026-10-02 · Owner: DishNet operations

This procedure takes a business from first enquiry to a working, tested
remote-Tally setup. The dashboard (`/admin/customers/<id>`) shows the same
stages with a **next action and owner**; use it as the live checklist and
this document for the "why" and the acceptance criteria.

The one message every customer must understand: **the connection links the
computers; Remote Desktop shows the office screen; Tally stays on the
office computer.**

## Roles

| Code | Role | Who at DishNet / customer |
|---|---|---|
| **SA** | Sales / admin | DishNet staff who talk to the customer first and manage the account |
| **TS** | Technical support | DishNet staff who verify the connection and run the acceptance test |
| **CIT** | Customer IT contact | The person at the customer who looks after the office computer (often the owner) |
| **ST** | Staff user | Each employee who will use Tally remotely |
| **AD** | DishNet administrator | Dashboard owner/operator role; billing, renewals, revocation |

## RACI

| Stage | SA | TS | CIT | ST | AD |
|---|---|---|---|---|---|
| 1 Enquiry, expectations, limitations | **R/A** | C | I | – | I |
| 2 Trial approval, codes/links | **R/A** | I | I | – | C |
| 3 Office computer readiness | C | **R** | **A** | – | – |
| 4 Office app install + "Allow Remote Desktop" | I | C | **R/A** | – | – |
| 5 Staff device install + activation | I | C | C | **R/A** | – |
| 6 Acceptance test (RDP sign-in + Tally) | I | **R** | C | **A** | – |
| 7 Handover (manual, support contact, update process) | I | **R/A** | I | I | – |
| 8 Ongoing: trial expiry, renewals, revocation, support | I | C | I | I | **R/A** |

R = does the work · A = accountable · C = consulted · I = informed

## Stage 1 — Enquiry (SA)

1. Explain in plain words what the service does and does not do (see
   manual §1). Say explicitly: *Tally stays on your office computer; you see
   it through Remote Desktop; the office computer must stay on.*
2. Ask the four qualifying questions and record answers in the dashboard notes:
   - Which computer runs Tally? **Which Windows edition** (Settings → System → About)? *Home = not supported as the office computer; recommend upgrading that PC to Pro, or another Pro PC.*
   - Does Tally work on it today, locally?
   - How many staff computers need access? (device limit)
   - Who is the IT contact, and can they keep the office PC on and online?
3. State the limitations honestly: one person at a time on a normal Windows
   PC; Windows Server needed for simultaneous users; DishNet does not
   support Tally itself.
4. If the customer came through `/trial`, the request is in **Trial
   requests**; otherwise create the customer in **Customers → New customer**
   (plan: 30-day trial by default).

**Acceptance:** customer record exists with contact name, phone, device
limit; notes record the Windows edition answer (or "to confirm").

## Stage 2 — Trial approval and links (SA)

1. **Trial requests → Approve** (or create codes on the customer page). This
   creates one **office** link and one **staff** link. They are shown once —
   copy both immediately.
2. Send the office link to the CIT and the staff link to the customer, with
   the manual (`https://vpn.dishnetuganda.com/guide.pdf`) and the support
   contact. Say which link is which.
3. Record in notes: date sent, to whom.

**Acceptance:** both links sent; note recorded. Links expire after 14 days —
re-issue if unused.

## Stage 3 — Office computer readiness (TS with CIT)

1. Confirm the Windows edition in the dashboard (**Onboarding → Office
   computer Windows edition**). If Home: stop here and go back to SA for the
   upgrade conversation.
2. Confirm with the CIT: Tally works locally; the PC will stay on (sleep
   disabled); each remote user has a Windows account **with a password** on
   that PC (Remote Desktop refuses empty passwords). DishNet never receives
   those passwords — the CIT gives them to staff directly.
3. Confirm internet at the office (Starlink or other) is working.

**Acceptance:** edition recorded as Pro/Server; CIT confirms the three points;
note recorded.

## Stage 4 — Office app install (CIT, TS on the phone if needed)

1. CIT opens the office link on the office PC, runs the installer (*More
   info → Run anyway*, UAC *Yes*). The app activates and shows **Connected**.
2. The app asks **"Allow Remote Desktop for DishNet users?"** and explains
   what it changes. **The CIT (or the owner) clicks Allow** — DishNet staff
   may click it on site only with the owner present. This is the explicit
   consent the product requires; never bypass it with scripts.
3. TS checks the dashboard: the gateway device appears **online** (handshake
   under 3 minutes) and the onboarding list shows *Staff access policy in
   place*.

**Acceptance:** gateway online in the dashboard; CIT confirms Allow was
clicked; note recorded.

**Escalate** to engineering if: the app shows "Problem" after a retry as
administrator, or the device never handshakes although the PC has internet
(collect the diagnostics zip from the app).

## Stage 5 — Staff device install (ST, with CIT)

1. Each staff member opens the staff link on their own computer and runs the
   installer. The 2-minute tour plays on first launch.
2. The app activates by itself and shows **Connected** after *Connect to
   Office*. The checklist shows **Office computer reachable** when the
   office PC answers.
3. One link covers the agreed number of computers; a used-up link needs a
   new one from SA.

**Acceptance:** each staff device appears in the dashboard (online when
connected); checklist on the device shows the office computer reachable.

## Stage 6 — Acceptance test (TS with ST and CIT)

Done once per customer with at least one real staff user, on the phone or on site:

1. ST clicks **Open Remote Desktop**, signs in with their own Windows account
   for the office PC. TS never asks for or notes the password.
2. ST opens Tally on the office desktop and performs a normal task (open the
   company, view a report).
3. ST ticks **✔ Remote Desktop worked** and **✔ Tally opened** in the app.
4. ST disconnects properly (close Tally company → close Remote Desktop →
   Disconnect) and reconnects once to prove repeatability.
5. TS records in the dashboard: **Readiness = Ready** (or *Needs attention*
   with the reason) and ticks **Acceptance test passed**.

**Acceptance:** readiness Ready + acceptance recorded. **A VPN handshake
alone is never acceptance.**

**Escalate** if: Remote Desktop cannot connect although the office PC is
online (check Allow was clicked and the policy exists), or sign-in fails
repeatedly (CIT must reset the Windows password — not DishNet).

## Stage 7 — Handover (TS)

1. Send the customer the manual (PDF) and confirm they know: the support
   contact; that updates arrive inside the app (*Update now*, no uninstall);
   how to add another computer (ask DishNet); to tell DishNet when staff leave.
2. Tick **Handover done** in the dashboard.

**Customer handover checklist** (read out and confirm):
- [ ] They can say in their own words what stays at the office and what Remote Desktop does
- [ ] Office PC stays on; someone knows to check it if staff cannot connect
- [ ] Each user has their own Windows password and keeps it private
- [ ] They know the trial end date and what happens then (access stops; renewal restores it within a minute)
- [ ] They have the manual and the support contact

## Stage 8 — Ongoing (AD)

- **Trial expiry:** the dashboard shows days left; the app shows it to the
  customer. Extend or mark paid on the customer page. Access stops
  automatically at expiry and resumes within a minute of renewal.
- **Staff leaves:** revoke that device on the customer page — it is cut off
  within a minute. Issue a new code for a replacement.
- **More computers:** raise the device limit, generate a new staff code.
- **Suspension (non-payment):** Suspend customer; all devices are cut off;
  Reactivate restores them.
- **Support:** use the **Support view** per customer; add a note for every
  contact. Escalation and hub procedures are in `admin-support-runbook.md`.
- **Offboarding:** Suspend, then after the retention period revoke all
  devices; the customer uninstalls the app (Apps & features).

## What DishNet staff must never do

- Ask for, write down or store any Windows or Tally password.
- Enable Remote Desktop or open firewall ports on a customer PC by script
  or by hand without the owner's explicit consent in the app or in writing.
- Share one activation code between two computers, or send codes to anyone
  other than the customer's named contacts.
- Tell a customer "it works" based on a handshake; only the acceptance test
  (Stage 6) counts.
