"""
telltale_helper.py -- the user-facing half of ask mode (#34 in agent.py).

Runs in the signed-in user's session (started at logon by install_windows.ps1). For each alert
the agent writes, it shows a dialog with the app, its location, what it tried to do, and
Close app / Run anyway / Send report, then writes the user's choice back for the agent.

Run:  pythonw telltale_helper.py
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk

IPC_DIR = os.environ.get("EDR_IPC_DIR", os.path.join(os.environ.get("ProgramData", "."), "Telltale"))
ALERTS_DIR = os.path.join(IPC_DIR, "alerts")
DECISIONS_DIR = os.path.join(IPC_DIR, "decisions")
POLL_S = 2
REMIND_S = 600   # re-show an alert whose window was closed without a choice


def decide(alert_id, choice, **extra):
    """Write the user's choice for the agent (atomic, so it never reads half a file)."""
    os.makedirs(DECISIONS_DIR, exist_ok=True)
    name = f"{alert_id}.{choice}"
    tmp = os.path.join(DECISIONS_DIR, name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"id": alert_id, "choice": choice, **extra}, f)
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
    root = themed_root("Haltline: suspicious app")
    p = root.palette
    root.attributes("-topmost", True)
    root.resizable(False, False)
    pad = {"padx": 16, "pady": 4, "anchor": "w"}

    # Everything shown comes from the flagged app (name, path): plain text labels only.
    tk.Label(root, text="Haltline found a suspicious app", font=("Segoe UI", 13, "bold")).pack(**{**pad, "pady": (14, 4)})
    tk.Label(root, text=alert["name"], font=("Segoe UI", 11, "bold")).pack(**pad)
    tk.Label(root, text=alert["path"] or "(location unknown)", wraplength=520, justify="left").pack(**pad)
    tk.Label(root, text="What it tried to do:", font=("Segoe UI", 10, "bold")).pack(**{**pad, "pady": (10, 2)})
    for line in alert["reasons"] or ["Its behavior matched known ransomware patterns"]:
        tk.Label(root, text="  • " + line, wraplength=520, justify="left").pack(**pad)
    tk.Label(root, text=f"Detection: {alert['reason']}", fg=p["muted"]).pack(**{**pad, "pady": (8, 2)})
    tk.Label(root, text="The app is still running until you choose.", fg=p["warn"]).pack(**pad)
    status = tk.Label(root, text="", fg=p["accent"])
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


LICENCE_TEXT = {
    "revoked": "this PC's licence was removed by your administrator",
    "invalid": "the licence key is not valid (it may have been deleted)",
    "full": "the licence key has no free PCs left",
}


def licence_notice(last_ts):
    """The agent's note that it stopped for a licence reason; (reason, ts) when it is new, else None."""
    try:
        with open(os.path.join(ALERTS_DIR, "licence.status"), encoding="utf-8") as f:
            note = json.load(f)
    except (OSError, ValueError):
        return None
    return (note.get("reason", ""), note.get("ts")) if note.get("ts") != last_ts else None


def show_licence(reason):
    root = themed_root("Haltline has stopped")
    root.attributes("-topmost", True)
    root.resizable(False, False)
    why = LICENCE_TEXT.get(reason, "the licence is no longer valid")
    tk.Label(root, text="Haltline is no longer protecting this PC", font=("Segoe UI", 13, "bold")).pack(padx=16, pady=(14, 4), anchor="w")
    tk.Label(root, text=f"It stopped because {why}.\nAsk your administrator for a valid key, then reinstall Haltline.",
             justify="left").pack(padx=16, pady=4, anchor="w")
    tk.Button(root, text="OK", width=10, command=root.destroy).pack(padx=16, pady=(8, 14), anchor="e")
    root.mainloop()


# ── Tray icon and "What Haltline sends" ─────────────────────────────────────────────────────────
SERVICE = "HaltlineAgent"
REQUESTS = queue.Queue()   # tray menu clicks -> main loop (tkinter must stay on the main thread)
TRAY = {}                  # the tray's window handle, to close it from the main loop
WM_OPEN = 0x0400 + 21      # WM_USER + 21: "open" from a second copy (Start menu / desktop)
WHAT = {"/v1/score": "Behaviour check", "/v1/register": "Registration", "/v1/report": "Report you chose to send"}
APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))


def read_sent(limit=100):
    """The agent's record of what this PC sent to the cloud (alerts\\sent.jsonl), newest first."""
    try:
        with open(os.path.join(ALERTS_DIR, "sent.jsonl"), encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out[::-1][:limit]


def service_running():
    """True / False, or None when the service isn't installed or can't be asked."""
    try:
        import win32serviceutil
        return win32serviceutil.QueryServiceStatus(SERVICE)[1] == 4   # SERVICE_RUNNING
    except Exception:
        return None


def set_service(action):
    """Start or stop the agent. Needs an administrator (UAC prompt), so a program running as the user,
    ransomware included, can't switch protection off this way. Ending the task in Task Manager doesn't
    work either: Windows restarts the service within a minute."""
    import win32api
    sc = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "sc.exe")
    try:
        win32api.ShellExecute(0, "runas", sc, f"{action} {SERVICE}", None, 0)
    except Exception:
        pass   # the user said No to UAC


# ── Look: follows Windows' light / dark setting unless the user picks one (saved per user) ──
SETTINGS = os.path.join(os.environ.get("APPDATA", "."), "Haltline", "settings.json")
THEMES = ("system", "light", "dark")
PALETTES = {
    "light": {"bg": "#f6f6f3", "panel": "#ffffff", "fg": "#1b1b1b", "muted": "#5a5a5a", "accent": "#1d6b2f",
              "warn": "#8a5a00", "line": "#d6d6d0", "sel": "#cfe3d4"},
    "dark": {"bg": "#1b1c1e", "panel": "#25272a", "fg": "#ececea", "muted": "#a7a7a2", "accent": "#7fcf95",
             "warn": "#e3b45e", "line": "#3a3d41", "sel": "#2e4a37"},
}


def load_theme():
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            t = json.load(f).get("theme")
        return t if t in THEMES else "system"
    except (OSError, ValueError, AttributeError):
        return "system"


def save_theme(theme):
    try:
        os.makedirs(os.path.dirname(SETTINGS), exist_ok=True)
        with open(SETTINGS, "w", encoding="utf-8") as f:
            json.dump({"theme": theme if theme in THEMES else "system"}, f)
    except OSError:
        pass


def system_theme():
    """Windows' app theme: 'dark' or 'light' (light when it can't be read)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return "light" if winreg.QueryValueEx(k, "AppsUseLightTheme")[0] else "dark"
    except OSError:
        return "light"


def palette(choice=None):
    c = choice or load_theme()
    return PALETTES[system_theme() if c == "system" else c]


def themed_root(title):
    """A Tk window in the current palette: classic widgets via the option database, ttk via a style."""
    from tkinter import ttk
    p = palette()
    root = tk.Tk()
    root.title(title)
    root.configure(bg=p["bg"])
    for k, v in (("*Background", p["bg"]), ("*Foreground", p["fg"]), ("*Button.Background", p["panel"]),
                 ("*Button.activeBackground", p["line"]), ("*Button.activeForeground", p["fg"]),
                 ("*Button.highlightBackground", p["bg"]), ("*Text.Background", p["panel"]),
                 ("*Text.insertBackground", p["fg"]), ("*selectBackground", p["sel"]), ("*selectForeground", p["fg"]),
                 ("*Font", "{Segoe UI} 10")):
        root.option_add(k, v)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Treeview", background=p["panel"], fieldbackground=p["panel"], foreground=p["fg"],
                    bordercolor=p["line"], rowheight=26, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background=p["bg"], foreground=p["muted"], bordercolor=p["line"],
                    relief="flat", font=("Segoe UI", 9, "bold"))
    style.map("Treeview", background=[("selected", p["sel"])], foreground=[("selected", p["fg"])])
    style.configure("TRadiobutton", background=p["bg"], foreground=p["fg"], font=("Segoe UI", 9))
    style.map("TRadiobutton", background=[("active", p["bg"])])
    style.configure("Vertical.TScrollbar", background=p["panel"], troughcolor=p["bg"], bordercolor=p["line"], arrowcolor=p["muted"])
    try:   # dark title bar too (Windows 10 2004+ / 11); ignored elsewhere
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        on = ctypes.c_int(1 if p is PALETTES["dark"] else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(on), ctypes.sizeof(on))
    except Exception:
        pass
    try:
        root.iconbitmap(default=os.path.join(APP_DIR, "haltline.ico"))
    except Exception:
        pass
    root.palette = p
    return root


def show_sent():
    from tkinter import ttk
    root = themed_root("What Haltline sends")
    p = root.palette
    root.geometry("1000x660")
    root.minsize(780, 500)

    top = tk.Frame(root)
    top.pack(fill="x", padx=20, pady=(16, 2))
    tk.Label(top, text="What Haltline sends from this PC", font=("Segoe UI", 15, "bold")).pack(side="left")
    choice = tk.StringVar(value=load_theme())
    themes = tk.Frame(top)
    themes.pack(side="right")
    tk.Label(themes, text="Theme", fg=p["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))

    def retheme():
        save_theme(choice.get())
        REQUESTS.put("sent")   # reopen in the new look
        root.destroy()

    for value, label in (("system", "System"), ("light", "Light"), ("dark", "Dark")):
        ttk.Radiobutton(themes, text=label, value=value, variable=choice, command=retheme).pack(side="left", padx=2)

    tk.Label(root, justify="left", wraplength=950, fg=p["muted"], text=(
        "Only the requests below leave your PC, never your files or what is in them. Most programs are decided on this PC. "
        "For an uncertain one, Haltline sends 99 numbers describing what it did in its first 30 seconds and gets back allow "
        "(BENIGN) or stop (KILL). The program's name, PID and location are shown here so you know which one it was; they are "
        "not sent. With every request the server also sees this PC's device ID and your IP address. The last 100 requests are kept.")
             ).pack(padx=20, pady=(2, 12), anchor="w")

    table = tk.Frame(root)
    table.pack(fill="x", padx=20)
    cols = (("time", "Time", 150), ("program", "Program", 210), ("pid", "PID", 70), ("what", "What", 190), ("answer", "Answer", 300))
    tree = ttk.Treeview(table, columns=[c[0] for c in cols], show="headings", height=9, selectmode="browse")
    for col, label, width in cols:
        tree.heading(col, text=label, anchor="w")
        tree.column(col, width=width, anchor="w", stretch=col in ("program", "answer"))
    bar = ttk.Scrollbar(table, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=bar.set)
    tree.pack(side="left", fill="x", expand=True)
    bar.pack(side="right", fill="y")
    tree.tag_configure("kill", foreground=p["warn"])

    about = tk.Label(root, text="", fg=p["muted"], justify="left", wraplength=950, font=("Segoe UI", 9))
    about.pack(padx=20, pady=(12, 2), anchor="w")
    tk.Label(root, text="Exactly what was sent", font=("Segoe UI", 10, "bold")).pack(padx=20, anchor="w")
    detail = tk.Text(root, wrap="none", height=12, font=("Consolas", 9), relief="flat", highlightthickness=1,
                     highlightbackground=p["line"], highlightcolor=p["line"], padx=8, pady=6)
    detail.pack(fill="both", expand=True, padx=20, pady=(2, 0))
    entries = []

    def fill():
        entries[:] = read_sent()
        tree.delete(*tree.get_children())
        for i, e in enumerate(entries):
            a = e.get("about") or {}
            tree.insert("", "end", iid=str(i), tags=("kill",) if e.get("result") == "KILL" else (), values=(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("ts", 0))), a.get("name") or "-",
                a.get("pid") or "-", WHAT.get(e.get("path"), e.get("path", "")), e.get("result", "")))
        if entries:
            tree.selection_set("0")
            tree.focus("0")
        else:
            about.config(text="")
            detail.delete("1.0", "end")
            detail.insert("end", "Nothing sent yet.")

    def pick(_e=None):
        sel = tree.selection()
        if not sel:
            return
        e = entries[int(sel[0])]
        a = e.get("about") or {}
        about.config(text=f"About (not sent): {a.get('name')}, PID {a.get('pid')}, {a.get('path') or 'location unknown'}"
                     if a else "Not about a program." if e.get("path") != "/v1/report" else "A report you chose to send.")
        detail.delete("1.0", "end")
        detail.insert("end", json.dumps(e.get("sent", {}), indent=2))   # plain text, never HTML

    tree.bind("<<TreeviewSelect>>", pick)
    buttons = tk.Frame(root)
    buttons.pack(fill="x", padx=20, pady=(10, 16))
    tk.Button(buttons, text="Report a problem...", width=18, relief="flat", command=lambda: report_problem(root)).pack(side="left")
    tk.Button(buttons, text="Close", width=12, relief="flat", command=root.destroy).pack(side="right", padx=(6, 0))
    tk.Button(buttons, text="Refresh", width=12, relief="flat", command=fill).pack(side="right")
    fill()
    root.mainloop()


def report_problem(parent=None):
    """'Report a problem': free text, handed to the agent, which sends it signed like other reports."""
    if parent is not None:
        win, p = tk.Toplevel(parent), parent.palette
        win.title("Report a problem")
        win.configure(bg=p["bg"])
        win.transient(parent)
        win.grab_set()
    else:
        win = themed_root("Report a problem")
        p = win.palette
    win.resizable(False, False)
    tk.Label(win, text="Report a problem", font=("Segoe UI", 13, "bold")).pack(padx=18, pady=(14, 4), anchor="w")
    tk.Label(win, wraplength=480, justify="left", fg=p["muted"], text=(
        "Tell us what doesn't work. It is sent with this PC's device ID, like other reports, and shows up in "
        "What Haltline sends. Please don't include passwords or personal details.")).pack(padx=18, anchor="w")
    box = tk.Text(win, width=62, height=8, wrap="word", relief="flat", highlightthickness=1,
                  highlightbackground=p["line"], highlightcolor=p["accent"], padx=6, pady=6)
    box.pack(padx=18, pady=(10, 4))
    box.focus_set()
    status = tk.Label(win, text="", fg=p["warn"])
    status.pack(padx=18, anchor="w")

    def send():
        text = box.get("1.0", "end").strip()
        if not text:
            status.config(text="Write a few words first.")
            return
        decide(f"problem-{int(time.time() * 1000)}", "problem", text=text[:1000])
        win.destroy()

    row = tk.Frame(win)
    row.pack(padx=18, pady=(6, 14), anchor="e")
    tk.Button(row, text="Cancel", width=12, relief="flat", command=win.destroy).pack(side="left", padx=4)
    tk.Button(row, text="Send", width=12, relief="flat", command=send).pack(side="left", padx=4)
    if parent is None:
        win.mainloop()


def confirm_start():
    from tkinter import messagebox
    root = themed_root("Haltline")
    root.withdraw()
    ok = messagebox.askyesno("Start Haltline?", "Haltline is stopped, so this PC is not protected.\n\n"
                             "Start it again? Windows will ask for an administrator.", parent=root)
    root.destroy()
    return ok


def confirm_stop():
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    ok = messagebox.askyesno("Stop Haltline?", "Haltline will stop protecting this PC until you start it again "
                             "or restart the PC.\n\nWindows will ask for an administrator.", icon="warning", parent=root)
    root.destroy()
    return ok


def taskbar_light():
    """Windows' taskbar theme (SystemUsesLightTheme), separate from the apps' theme."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return bool(winreg.QueryValueEx(k, "SystemUsesLightTheme")[0])
    except OSError:
        return False


def tray_icon(running):
    """The Haltline mark for the tray: cream on a dark taskbar, ink on a light one, grey while stopped."""
    import win32con
    import win32gui
    name = f"haltline-tray-{'' if running else 'off-'}{'light' if taskbar_light() else 'dark'}.ico"
    path = os.path.join(APP_DIR, name)
    try:
        return win32gui.LoadImage(0, path, win32con.IMAGE_ICON, 0, 0, win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE)
    except Exception:   # running from source without the icons: stock icons
        return win32gui.LoadIcon(0, 32518 if running else win32con.IDI_WARNING)   # 32518 = IDI_SHIELD


def run_tray():
    """The notification-area icon (pywin32, already a dependency). Runs its own message loop on this thread."""
    import ctypes
    import win32api
    import win32con
    import win32gui
    WM_TRAY = win32con.WM_USER + 20
    taskbar_created = win32gui.RegisterWindowMessage("TaskbarCreated")   # Explorer restarted: add the icon again
    state = {"running": service_running()}
    items = {1: "sent", 2: "privacy", 3: "stop", 4: "start", 5: "quit", 6: "problem"}

    def tip():
        return "Haltline: protecting this PC" if state["running"] else "Haltline: not protecting this PC"

    def notify(hwnd, msg):
        icon = tray_icon(state["running"])
        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        win32gui.Shell_NotifyIcon(msg, (hwnd, 0, flags, WM_TRAY, icon, tip()))

    def on_tray(hwnd, msg, wparam, lparam):
        if lparam in (win32con.WM_RBUTTONUP, win32con.WM_LBUTTONUP):
            menu = win32gui.CreatePopupMenu()
            win32gui.AppendMenu(menu, win32con.MF_STRING | win32con.MF_GRAYED, 0, tip())
            win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
            win32gui.AppendMenu(menu, win32con.MF_STRING, 1, "What Haltline sends...")
            win32gui.AppendMenu(menu, win32con.MF_STRING, 6, "Report a problem...")
            win32gui.AppendMenu(menu, win32con.MF_STRING, 2, "Privacy notice")
            win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
            if state["running"]:
                win32gui.AppendMenu(menu, win32con.MF_STRING, 3, "Stop Haltline... (needs admin)")
            else:
                win32gui.AppendMenu(menu, win32con.MF_STRING, 4, "Start Haltline... (needs admin)")
                win32gui.AppendMenu(menu, win32con.MF_STRING, 5, "Close this icon")
            x, y = win32gui.GetCursorPos()
            win32gui.SetForegroundWindow(hwnd)
            win32gui.TrackPopupMenu(menu, win32con.TPM_LEFTALIGN, x, y, 0, hwnd, None)
            win32gui.PostMessage(hwnd, win32con.WM_NULL, 0, 0)
        return 0

    def on_command(hwnd, msg, wparam, lparam):
        if items.get(win32api.LOWORD(wparam)):
            REQUESTS.put(items[win32api.LOWORD(wparam)])
        return 0

    def on_timer(hwnd, msg, wparam, lparam):
        now, light = service_running(), taskbar_light()
        if (now, light) != (state["running"], state.get("light")):
            state["running"], state["light"] = now, light   # follows a theme change too
            notify(hwnd, win32gui.NIM_MODIFY)
        return 0

    def on_taskbar(hwnd, msg, wparam, lparam):
        notify(hwnd, win32gui.NIM_ADD)
        return 0

    def on_open(hwnd, msg, wparam, lparam):
        REQUESTS.put("open")   # Haltline opened again from Start / the desktop
        return 0

    def on_destroy(hwnd, msg, wparam, lparam):
        win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (hwnd, 0))
        win32gui.PostQuitMessage(0)
        return 0

    wc = win32gui.WNDCLASS()
    wc.hInstance = win32api.GetModuleHandle(None)
    wc.lpszClassName = "HaltlineTray"
    wc.lpfnWndProc = {WM_TRAY: on_tray, win32con.WM_COMMAND: on_command, win32con.WM_TIMER: on_timer,
                      taskbar_created: on_taskbar, WM_OPEN: on_open, win32con.WM_DESTROY: on_destroy}
    win32gui.RegisterClass(wc)
    hwnd = win32gui.CreateWindow(wc.lpszClassName, "Haltline", 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
    TRAY["hwnd"] = hwnd
    notify(hwnd, win32gui.NIM_ADD)
    ctypes.windll.user32.SetTimer(hwnd, 1, 5000, None)   # follow the service state every 5 s
    win32gui.PumpMessages()


def handle(request):
    """A tray menu click, on the main thread. Returns False when the helper should exit."""
    if request == "open":   # from Start / the desktop: stopped -> offer to start, else the window
        if service_running() is False and confirm_start():
            set_service("start")
        else:
            show_sent()
    elif request == "sent":
        show_sent()
    elif request == "problem":
        report_problem()
    elif request == "privacy":
        subprocess.Popen(["notepad.exe", os.path.join(APP_DIR, "PRIVACY.md")])
    elif request == "stop" and confirm_stop():
        set_service("stop")
    elif request == "start":
        set_service("start")
    elif request == "quit" and not service_running():
        import win32con
        import win32gui
        win32gui.PostMessage(TRAY["hwnd"], win32con.WM_CLOSE, 0, 0)
        return False
    return True


def single_instance():
    """False when another copy already runs in this session (e.g. opened again from the Start menu)."""
    import win32api
    import win32event
    import winerror
    single_instance.mutex = win32event.CreateMutex(None, False, "Local\\HaltlineHelper")
    return win32api.GetLastError() != winerror.ERROR_ALREADY_EXISTS


def main():
    opened = "--open" in sys.argv   # started from the Start menu / desktop shortcut, not at sign-in
    if not single_instance():
        if opened:   # the tray already runs: ask it to open instead of adding a second icon
            import win32gui
            hwnd = win32gui.FindWindow("HaltlineTray", None)
            if hwnd:
                win32gui.PostMessage(hwnd, WM_OPEN, 0, 0)
        return
    threading.Thread(target=run_tray, name="Tray", daemon=True).start()
    if opened:
        REQUESTS.put("open")
    shown = {}
    licence_ts = None
    while True:
        note = licence_notice(licence_ts)
        if note:
            licence_ts = note[1]
            show_licence(note[0])
        for alert in due_alerts(shown, time.time()):
            shown[alert["id"]] = time.time()
            show(alert)   # one dialog at a time; the others queue
        try:
            request = REQUESTS.get(timeout=POLL_S)
        except queue.Empty:
            continue
        if not handle(request):
            return


if __name__ == "__main__":
    main()
