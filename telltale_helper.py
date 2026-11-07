"""
telltale_helper.py -- the user-facing half of ask mode (#34 in agent.py).

Runs in the signed-in user's session (started at logon by install_windows.ps1). For each alert
the agent writes, it shows a dialog with the app, its location, what it tried to do, and
Close app / Run anyway / Send report, then writes the user's choice back for the agent.

Run:  pythonw telltale_helper.py
"""
import json
import os
import time
import tkinter as tk

IPC_DIR = os.environ.get("EDR_IPC_DIR", os.path.join(os.environ.get("ProgramData", "."), "Telltale"))
ALERTS_DIR = os.path.join(IPC_DIR, "alerts")
DECISIONS_DIR = os.path.join(IPC_DIR, "decisions")
POLL_S = 2
REMIND_S = 600   # re-show an alert whose window was closed without a choice


def decide(alert_id, choice):
    """Write the user's choice for the agent (atomic, so it never reads half a file)."""
    os.makedirs(DECISIONS_DIR, exist_ok=True)
    name = f"{alert_id}.{choice}"
    tmp = os.path.join(DECISIONS_DIR, name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"id": alert_id, "choice": choice}, f)
    os.replace(tmp, os.path.join(DECISIONS_DIR, name + ".json"))


def due_alerts(shown, now):
    """Alerts still open that were never shown, or were dismissed more than REMIND_S ago."""
    if not os.path.isdir(ALERTS_DIR):
        return []
    out = []
    for fn in sorted(os.listdir(ALERTS_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(ALERTS_DIR, fn), encoding="utf-8") as f:
                alert = json.load(f)
        except (OSError, ValueError):
            continue
        if now - shown.get(alert["id"], -REMIND_S) >= REMIND_S:
            out.append(alert)
    return out


def show(alert):
    """One alert dialog. Returns when the user picks Close / Run, or closes the window."""
    root = tk.Tk()
    root.title("Telltale: suspicious app")
    root.attributes("-topmost", True)
    root.resizable(False, False)
    pad = {"padx": 16, "pady": 4, "anchor": "w"}

    # Everything shown comes from the flagged app (name, path): plain text labels only.
    tk.Label(root, text="Telltale found a suspicious app", font=("Segoe UI", 13, "bold")).pack(**{**pad, "pady": (14, 4)})
    tk.Label(root, text=alert["name"], font=("Segoe UI", 11, "bold")).pack(**pad)
    tk.Label(root, text=alert["path"] or "(location unknown)", wraplength=520, justify="left").pack(**pad)
    tk.Label(root, text="What it tried to do:", font=("Segoe UI", 10, "bold")).pack(**{**pad, "pady": (10, 2)})
    for line in alert["reasons"] or ["Its behavior matched known ransomware patterns"]:
        tk.Label(root, text="  • " + line, wraplength=520, justify="left").pack(**pad)
    tk.Label(root, text=f"Detection: {alert['reason']}", fg="#555555").pack(**{**pad, "pady": (8, 2)})
    tk.Label(root, text="The app is still running until you choose.", fg="#8a5a00").pack(**pad)
    status = tk.Label(root, text="", fg="#1d6b2f")
    status.pack(**pad)

    def choose(choice):
        decide(alert["id"], choice)
        if choice == "report":
            status.config(text="Report saved. Now choose Close app or Run anyway.")
            report_btn.config(state="disabled")
        else:
            root.destroy()

    buttons = tk.Frame(root)
    buttons.pack(padx=16, pady=(8, 14), anchor="e")
    report_btn = tk.Button(buttons, text="Send report", width=14, command=lambda: choose("report"))
    report_btn.pack(side="left", padx=4)
    tk.Button(buttons, text="Run anyway", width=14, command=lambda: choose("run")).pack(side="left", padx=4)
    close_btn = tk.Button(buttons, text="Close app", width=14, command=lambda: choose("close"))
    close_btn.pack(side="left", padx=4)
    close_btn.focus_set()
    root.bind("<Return>", lambda _e: choose("close"))
    root.mainloop()


def main():
    shown = {}
    while True:
        for alert in due_alerts(shown, time.time()):
            shown[alert["id"]] = time.time()
            show(alert)   # one dialog at a time; the others queue
        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
