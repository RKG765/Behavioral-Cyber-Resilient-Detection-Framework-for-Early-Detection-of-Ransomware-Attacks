# Running the Haltline beta

## 1. Pick testers
5 to 20 people with a Windows 10 or 11 (64-bit) PC they use every day, who will tell you when
something goes wrong. Avoid PCs that hold work you can't afford to interrupt: this is a first beta.

## 2. Make each one a licence key
Dashboard (https://haltline-console.pages.dev) → **Licences** → Seats `1` → **Create licence** →
**Copy**. The key is shown once; paste it straight into your message. One key per tester (one seat),
so you can see each person's PC under **Devices** and revoke one without affecting the others.

## 3. Send this message
> Hi! Thanks for trying Haltline, a ransomware detector for Windows that asks before it stops a
> suspicious program.
>
> 1. Download the installer: https://github.com/RKG765/Behavioral-Cyber-Resilient-Detection-Framework-for-Early-Detection-of-Ransomware-Attacks/releases/latest
> 2. Run it. Windows will say "Unknown publisher" (it's a test signature): choose **More info → Run anyway**.
> 3. Accept the privacy notice and paste your licence key: `HL-XXXXX-XXXXX-XXXXX-XXXXX`
> 4. Use your PC normally for two weeks. If a Haltline window ever asks about a program, tell me what it
>    was and what you chose.
>
> Privacy: only behaviour numbers for uncertain programs leave your PC, never your files. Full notice:
> PRIVACY.md in the repository. Questions: nobigoda@gmail.com

## 4. Collect feedback (ask after week 1 and week 2)
- Did the installer work first time? Anything confusing?
- Did a Haltline alert appear? Which program, and was it really suspicious?
- Did your PC feel slower?
- Anything you didn't trust or understand?

Watch the dashboard too: **Devices** (is everyone registered and recently seen?), **Rejected**
(errors), **Reports** (programs testers sent you).

## 5. Before the next round
Fix what testers hit, bump `AGENT_VERSION` in `agent.py`, rebuild with `packaging\build.ps1`,
publish a new pre-release, and (once an update URL is set) installed PCs update themselves.
