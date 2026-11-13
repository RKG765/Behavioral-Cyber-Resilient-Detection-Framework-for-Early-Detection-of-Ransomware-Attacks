HALTLINE PRIVACY NOTICE (beta)

Haltline watches programs that start on this PC and stops ransomware-like behaviour. Most checks run
on this PC. This notice says what leaves your PC, why, where it goes and how long it is kept.

1. WHAT IS SENT, AND WHEN

When you install Haltline (once):
  - your licence key, and a public key that this PC creates (the private key stays in the PC's TPM
    security chip, or in Windows' protected key store if there is no TPM);
  - the IP address the request comes from (every internet request carries one).

When a program looks suspicious but the PC can't be sure (rare):
  - 99 numbers that describe what the program did in its first seconds (for example how many files it
    renamed, or whether it changed the registry). No file contents, no file names, no user names;
    user folder names are masked before the numbers are made;
  - this PC's device ID, the time, and the IP address, country and network operator the request
    comes from.
  The numbers are scored and then discarded; they are not stored.

Only when you click "Send report" in a Haltline alert:
  - the program's name, its location on disk, its SHA-256 fingerprint, and the reasons Haltline
    showed you.

Haltline never sends documents, photos, keystrokes, browsing history or passwords.

You can check this yourself: right-click the Haltline icon next to the clock and choose
"What Haltline sends". It lists the last 100 requests this PC sent, each exactly as sent (your
licence key hidden), and the answer that came back.

2. WHERE IT GOES

  - Cloudflare (worldwide network) receives the requests and runs the first check.
  - Amazon Web Services in Mumbai, India (ap-south-1) stores the device record and the logs below,
    and answers if Cloudflare is unavailable.

3. HOW LONG IT IS KEPT

  - Request logs (device ID, time, IP, country, network, verdict): 90 days, then deleted
    automatically.
  - Reports you chose to send: 90 days.
  - Which IP addresses each device used: kept while the device is registered.
  - Your device record (device ID, public key, first IP, licence): while the device is registered.

4. WHO CAN SEE IT

Only Haltline's administrators, through a console protected by two separate logins, each with a
second factor. Every administrator action is recorded. The data is not sold or shared for
advertising.

5. YOUR CHOICES

  - You can uninstall Haltline at any time (Settings > Apps). It stops sending anything at once.
  - To have your device record, logs and reports deleted, or for any privacy question, email
    nobigoda@gmail.com and quote your device ID. The ID is in agent.log in the Haltline install
    folder, on the line "Cloud Tier 2: ... device <ID>". We delete them within 30 days.

6. ON THIS PC

Haltline keeps its own log in its install folder and its alerts in C:\ProgramData\Telltale. They
stay on this PC. Microsoft Sysmon, which Haltline installs, records program activity in the Windows
event log on this PC only.

By clicking "I accept" you agree to this data being sent and kept as described above, and to the
Sysinternals licence terms for Microsoft Sysmon, which the installer downloads from Microsoft
(https://learn.microsoft.com/sysinternals/license-terms).
