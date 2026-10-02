# DishNet Secure Connect — Help

## What is DishNet Secure Connect?
DishNet Secure Connect is a small program that gives your computer a private, encrypted road to your office computer. It is not Tally and it does not show Tally by itself. Tally and your company data stay on the office computer, exactly as today.

Think of it in two parts: the **connection** (DishNet makes the private road) and **Remote Desktop** (the Windows tool that shows you the office screen so you can work on that computer from where you are).

## How does it work?
1. **Your office computer** keeps Tally and the company data. It must stay switched on and connected to the internet, and DishNet must be set up on it as the "office computer".
2. **DishNet** connects your laptop to the office through an encrypted tunnel. Only devices that DishNet has authorised for your business can use it. Nobody else — not even other DishNet customers — can reach your office computer.
3. **Remote Desktop** shows you the office computer's screen. You sign in with your Windows user name and password for that computer, open Tally there, and work as if you were sitting in the office. Nothing is copied to your laptop.

Click **How does this work?** in the app any time to watch the short tour again.

## Set up Tally remote access, step by step
The app has a guided workflow for exactly this: click **Set up Tally remote access** on the main screen. It walks you through one complete practice run and shows which steps the software has checked (green ✔) and which you confirm yourself.

1. **Activate this laptop** — happens by itself from your install link (or type your code once).
2. **Connect to Office** — opens the private connection. This does not open Tally yet.
3. **Office computer reachable** — the app tests that the office computer answers. If not, the office computer is off, offline, or Remote Desktop was not allowed there.
4. **Open Remote Desktop** — one click; Windows opens it with the office address filled in.
5. **Sign in** with the Windows user name and password you use on the office computer. DishNet never asks for it.
6. **Open Tally and select your company** — the app names the company DishNet recorded for you. Tally and the data stay on the office computer.
7. **Do one simple task** you are authorised to do (for example view a report), to prove it really works.
8. **Finish properly** — close the company in Tally, close the Remote Desktop window, then click Disconnect.

After the practice run, daily use is just: **Connect to Office → Open Remote Desktop → sign in → Tally.** You can practise again any time from the same screen.


## How to connect for the first time
1. Install DishNet Secure Connect from the link DishNet sent you (Windows will ask for administrator permission once — this is needed to set up the secure connection).
2. If the app asks for an activation code, type the code DishNet gave you. Codes work once and only on this computer. If you used an install link, this happens by itself.
3. Click **Connect to Office**. Within a few seconds the status shows **Connected**.
4. Follow the checklist on the main screen: it tells you the next step and confirms when your office computer answers.

## How to access Tally remotely
1. Make sure the app shows **Connected** and the checklist says the office computer is reachable.
2. Click **Open Remote Desktop**. Windows Remote Desktop opens with the office computer's address filled in.
3. Sign in with the **Windows user name and password of the office computer** (the same ones used at the office). DishNet never asks for, stores or sees this password.
4. The office desktop appears in a window. Open Tally there as you normally do. Tally runs on the office computer; you are seeing and controlling it.
5. Tick the checklist steps once Remote Desktop and Tally work, so DishNet knows your setup is complete.

Tip: if the Remote Desktop window is small, use the full-screen button at the top of that window.

## How to disconnect safely
1. In Tally, save your work and close the company as you would at the office.
2. Close the Remote Desktop window (or sign out of Windows inside it).
3. Click **Disconnect** in DishNet Secure Connect.

Disconnecting only closes your private road. The office computer stays on and keeps running for your colleagues.

## What to do when the connection fails
Click **Something is not working…** on the main screen. The troubleshooting assistant checks what it can see (activation, the connection, the office computer) and asks you at most three questions to find which of six layers is failing — and who can fix it:

| Layer | Who fixes it |
|---|---|
| 1 Activation (code, revoked, trial ended) | DishNet |
| 2 DishNet connection (your internet) | You |
| 3 Office computer (off, offline, Allow not clicked, Windows Home) | The office |
| 4 Remote Desktop (does not open / refused) | You, then the office |
| 5 Windows sign-in (wrong user name or password) | Your office IT contact |
| 6 Tally itself (licence, company file) | Your Tally provider |

The most common cases:
- **"Connecting…" never becomes "Connected":** check that your laptop has internet (open any website). The office connection needs the internet on both sides.
- **"Reconnecting…":** your internet dropped. The app reconnects by itself when the internet is back; you do not need to click anything.
- **"Office computer not answering":** the office computer is probably switched off, asleep, or lost its internet. Ask someone at the office to switch it on and check that DishNet shows "Connected" there. Remote Desktop must be allowed on it (the office app asks for this once).
- **Remote Desktop opens but sign-in fails:** the user name or password of the office computer is wrong. Use the same ones that work at the office. DishNet cannot reset Windows passwords.
- **"Access revoked" or "trial has ended":** DishNet has stopped this device or your trial finished. Contact DishNet.
- **"Problem" with a message:** read the message; most are solved by closing and reopening the app as administrator. If it keeps happening, click **Save diagnostics…** and send the file to DishNet support. The file contains no passwords or keys.

## How to add another authorised computer
Each computer needs its own activation. Ask DishNet for a new install link or code for the extra computer. Your business has a limit on the number of computers; DishNet can raise it. Never share one code between two computers — a code works once.

## How updates work
DishNet Secure Connect checks for updates once a day. When a new version is available, a yellow bar appears with **Update now**. Click it: the update downloads from DishNet, installs in about a minute, and the app reopens. You do not need to uninstall anything, and your activation stays.

## Security, privacy and data location
- Your Tally data stays on your office computer. DishNet does not store, read or copy it.
- The connection is encrypted end to end using WireGuard®, a modern, widely audited protocol.
- Each computer has its own key, created on that computer. The private key never leaves it, not even to DishNet.
- Only computers authorised for **your** business can reach your office computer. Other DishNet customers are completely separate.
- DishNet never asks for your Windows password or Tally password, and the app never records them.
- Diagnostics files you send to support contain technical status only; secrets are removed automatically.

## Frequently asked questions
**Does the office computer have to be on all the time?** Yes, whenever someone needs to work remotely. If it is off or asleep, nobody can connect.

**Can two people use Tally remotely at the same time?** Remote Desktop on a normal Windows Pro PC allows one person at a time to control the screen. If a colleague is working, you will be asked whether to disconnect them. For several people at once, DishNet must assess Windows Server with Remote Desktop Services, its licensing, and how your Tally is set up — this is a separate assessment, not something the connection alone provides.

**Does this work with my version of Tally?** DishNet Secure Connect does not change Tally; it shows you the office screen. Whatever works on the office computer works remotely. DishNet confirms this with you during the first test.

**My office computer runs Windows Home. Will it work?** Windows Home cannot accept Remote Desktop connections. The recommended fix is to upgrade that computer to Windows Pro (a licence upgrade, no reinstall); otherwise use another office computer that runs Pro. DishNet can advise.

**Is my internet fast enough?** Remote Desktop works well even on modest connections, including Starlink. Large files are not transferred — only the screen.

**What does it cost after the trial?** Contact DishNet; the app shows how many trial days remain.

**How do I get help?** Use **Contact DishNet support** in the app.
