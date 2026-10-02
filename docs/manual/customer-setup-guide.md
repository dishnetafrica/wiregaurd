# {{title}}

Version {{version}} · {{date}} · Support: {{support_contact}}

## 1. What the service does — and does not do

**DishNet Secure Connect** gives an authorised computer a private, encrypted
connection to your office computer. You then use **Windows Remote Desktop** to
see and control the office computer and run Tally there, just as if you were
sitting at it.

| It does | It does not |
|---|---|
| Connect your laptop to your office securely, from anywhere with internet | Copy Tally or your company data to your laptop |
| Let only computers authorised for *your* business use the connection | Let other DishNet customers see your office |
| Keep working across internet drops — it reconnects by itself | Show Tally by itself — Remote Desktop does that |
| Update itself when DishNet publishes a new version | Replace Tally, change Tally, or need any Tally setting |

**The one idea to remember:** the connection links the computers; Remote
Desktop shows the office screen; Tally runs on the office computer.

## 2. How it fits together

{{diagram}}

1. **Office computer** — keeps Tally and the data. Must stay on and online.
2. **DishNet** — the encrypted connection between your devices and the office. Only your authorised computers can use it.
3. **Your laptop** — sees and controls the office screen through Remote Desktop. Nothing is stored on it.

## 3. Before you start — requirements

**Office computer (the one with Tally)**

- Windows 10 or 11 **Pro**, or Windows Server. *Windows Home cannot accept Remote Desktop connections.* The recommended fix is to upgrade that computer to Windows Pro (a licence upgrade, no reinstall); otherwise use another office computer that runs Pro. DishNet can advise.
- Switched on and connected to the internet whenever staff need remote access. Turn off sleep/hibernate in Windows power settings.
- A Windows user account with a password for each person who will sign in remotely (Remote Desktop refuses accounts with no password).
- Tally already installed and working on this computer.

**Each remote computer (staff laptops)**

- Windows 10 or 11 (64-bit), any edition, with an administrator account to install the app once.
- Internet access (Starlink, mobile data, office Wi-Fi — any).
- The Windows user name and password of the office computer (kept by the staff member, never given to DishNet).

**From DishNet**

- An install link (or activation code) for the office computer, and one for your staff computers.
- The number of computers you are allowed is agreed with DishNet; each needs its own activation.

## 4. Setting up the office computer

1. On the office computer, open the **office install link** DishNet sent you. The file `DishNetSecureConnect-Setup-DN-….exe` downloads.
2. Run it. Windows shows *"Windows protected your PC"* — click **More info → Run anyway** (the pilot build is not yet code-signed). Click **Yes** when Windows asks for administrator permission; it is needed once to install the secure connection.
3. The app opens, activates by itself, and shows **Connected**.
4. The app then asks: **"Allow Remote Desktop for DishNet users?"** It explains exactly what it will change: switch on Windows Remote Desktop, and allow connections *only from DishNet-authorised devices* on the Remote Desktop port. Nothing is opened to the internet. Click **Allow** (the owner of the computer, or DishNet support with the owner present, makes this choice).
5. Leave the app running. It starts with Windows and reconnects by itself. The office computer is now reachable by your staff.

> If you prefer to set Remote Desktop yourself instead of clicking Allow, use Windows Settings → System → Remote Desktop, and allow the DishNet connection range in Windows Firewall. DishNet support can walk you through it.

## 5. Installing and activating a staff computer

1. On the staff laptop, open the **staff install link**. Run the downloaded file (*More info → Run anyway*, then **Yes**).
2. The app opens with a short **2-minute tour** explaining the three steps. Watch it or choose *Watch later*; you can replay it any time with **How does this work?**
3. The app activates by itself (if you were given a code instead, type it and click **Activate**). Each code works once and registers only that computer.
4. The main screen shows your business name, this device, and **Your setup checklist**.

## 6. Connecting

1. Click **Connect to Office**. Within a few seconds the status reads **Connected**.
2. The checklist updates by itself:
   - ✔ Activation code accepted
   - ✔ Device registered
   - ✔ Secure connection to DishNet
   - **Office computer reachable** — the app tests whether the office computer answers. If it says *not answering*, the office computer is off, asleep, offline, or Remote Desktop was not allowed there yet.
3. **Next:** the line under the checklist always tells you what to do next.

## 7. Opening Remote Desktop and using Tally

1. Click **Open Remote Desktop**. Windows Remote Desktop opens with the office computer's address already filled in.
2. Click **Connect**, then sign in with the **Windows user name and password of the office computer**. If Windows warns that the computer's identity cannot be verified, choose *Yes* — you are connecting through DishNet's private connection, not the public internet.
3. The office desktop appears in a window (use the full-screen button at the top if it is small). Open Tally there exactly as you do at the office.
4. Back in the DishNet app, tick **✔ Remote Desktop worked** and **✔ Tally opened** so DishNet knows your setup is complete.

Only one person at a time can control a normal Windows PC through Remote Desktop. If a colleague is working on it, you will be asked whether to disconnect them — agree with them first.

## 8. Disconnecting

1. In Tally, save and close the company as usual.
2. Close the Remote Desktop window (or sign out inside it).
3. Click **Disconnect** in the DishNet app.

The office computer keeps running for others. You can leave the DishNet app open; it uses no data when idle.

## 9. When something does not work

Start at the top and stop at the first line that matches what you see.

| What you see | What it usually means | What to do |
|---|---|---|
| **"Connecting…" for more than a minute** | Your laptop has no internet | Open any website. Fix your internet first; the app connects by itself afterwards. |
| **"Reconnecting…"** | Your internet dropped | Wait. The app reconnects by itself when the internet is back. |
| **"Office computer not answering"** | Office PC off, asleep, offline, or Remote Desktop not allowed there | Ask someone at the office to switch it on and check the DishNet app there shows Connected and Remote Desktop was allowed. |
| **Remote Desktop opens, sign-in fails** | Wrong Windows user name/password of the office computer, or the account has no password | Use the office computer's own login. Set a password on that Windows account if it has none. |
| **"Access revoked"** | DishNet removed this device | Contact DishNet. A new install link/code is needed. |
| **"Free trial has ended"** | Your trial finished | Contact DishNet to continue; access returns within a minute of renewal. |
| **"Problem" with a message** | A local issue (permissions, tunnel component) | Close the app, right-click → Run as administrator. If it persists, click **Save diagnostics…** and send the file to DishNet. |
| **Yellow bar "Version X is available"** | An update is ready | Click **Update now**. No uninstall needed; activation stays. |

Tally itself behaves exactly as it does at the office. Tally questions (licences, company files, errors inside Tally) are for your Tally provider; DishNet supports the connection and Remote Desktop.

## 10. Security tips and support

- Never share your activation code or install link; each works once per computer.
- Never give your Windows or Tally password to anyone — DishNet will never ask for it.
- Lock your laptop when you step away; anyone using it could reach the office through the connection.
- Disconnect when you finish for the day.
- When a staff member leaves, tell DishNet; their device is removed within a minute.
- Keep the office computer updated and protected with antivirus, as for any business computer.
- Your data stays on your office computer. DishNet does not store, read or copy it; the connection is encrypted end to end (WireGuard®). Diagnostics files you send contain technical status only — secrets are removed automatically.

**Contact DishNet support:** {{support_contact}}{{support_email_line}}
Tell us your business name and what the app shows. Use **Save diagnostics…** in the app if we ask for the file.

---

## Appendix — Help topics (as shown in the app)

{{help_topics}}
