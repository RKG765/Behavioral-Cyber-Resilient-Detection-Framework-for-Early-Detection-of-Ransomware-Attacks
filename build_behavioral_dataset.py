"""
build_behavioral_dataset.py
===========================
Rebuilds the training set with GENERALIZABLE BEHAVIORAL FEATURES.

What it fixes (found in an earlier audit of the raw image paths):
  * DROPS every Splunk-forwarder process (lab monitoring agent mislabeled as malware)
  * NEVER feeds raw Image / ParentImage / path / user strings to a model;
    only booleans, categories (mapped) and log-scaled counts are produced
  * Usernames are SANITIZED (\\users\\<anything> -> \\users\\<user>) before any
    path heuristic, so a user/profile name can never become a label shortcut
  * Events are ordered by SystemTime (UtcTime in the CSV is truncated to mm:ss.f
    and mis-orders events across hours)

Per process (ProcessGuid), over its FIRST 50 events (+ its EventID-1 row):
  sequence       : EventIDs 1..23, padded to 50
  cmdline        : has_base64, has_powershell_bypass, length>200, has_http_download, ...
  path context   : is_executing_from_temp, is_system_binary_wrong_path, user-writable, ...
  parent/child   : mapped CATEGORIES (office/shell/browser/system/...) + risky pairs
  network        : is_external_ip fraction, unique dests, suspicious ports
  timing         : inter-event delta statistics (burst vs human speed)
  file/reg/dns/image-load/process-access aggregates

Output : dataset/behavioral_dataset.npz  +  dataset/behavioral_dataset_meta.json
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
import os, re, json, time, math, ipaddress
import numpy as np
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
CSV = os.path.join("dataset", "LMD-2023 [1.87M Elements]", "LMD-2023 [1.87M Elements]Checked",
                   "Labelled LMD-2023", "LMD-2023 [1.87M Elements][Labelled]checked.csv")
OUT_NPZ = os.path.join("dataset", "behavioral_dataset.npz")
OUT_META = os.path.join("dataset", "behavioral_dataset_meta.json")
WINDOW, MIN_LEN, SEED = 50, 3, 42
CHUNK = 250_000


def ts():
    return time.strftime("%H:%M:%S")


# ───────────────────────── sanitization & helpers ─────────────────────────
_USER_RE = re.compile(r"\\users\\[^\\]+", re.I)
_DOCS_RE = re.compile(r"\\documents and settings\\[^\\]+", re.I)


def sanitize(s):
    """lower-case + replace profile names so usernames carry no signal."""
    if not isinstance(s, str):
        return ""
    s = s.strip().lower()
    if s in ("-", "0", "nan"):
        return ""
    s = _USER_RE.sub(r"\\users\\<user>", s)
    return _DOCS_RE.sub(r"\\documents and settings\\<user>", s)


def san_series(s):
    s = s.fillna("").astype(str).str.strip().str.lower()
    s = s.where(~s.isin(["-", "0", "nan"]), "")
    s = s.str.replace(r"\\users\\[^\\]+", r"\\users\\<user>", regex=True)
    return s.str.replace(r"\\documents and settings\\[^\\]+", r"\\documents and settings\\<user>",
                         regex=True)


def base_of(p):
    return re.split(r"[\\/]", p)[-1] if p else ""


def entropy(s):
    if not s:
        return 0.0
    c = {}
    for ch in s:
        c[ch] = c.get(ch, 0) + 1
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def self_test():
    a = sanitize(r"C:\Users\Alice.Smith\AppData\Local\Temp\x.exe")
    b = sanitize(r"C:\USERS\chrsm\AppData\Local\Temp\x.exe")
    assert a == b == r"c:\users\<user>\appdata\local\temp\x.exe", (a, b)
    print("  [OK] username sanitization self-test passed")


# ───────────────────────── name -> category maps ─────────────────────────
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
          "onenote.exe", "mspub.exe", "visio.exe"}
SHELL = {"cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe"}
SCRIPT = {"wscript.exe", "cscript.exe", "mshta.exe"}
BROWSER = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
           "brave.exe", "vivaldi.exe"}
SYSTEM = {"svchost.exe", "services.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
          "taskhostw.exe", "smss.exe", "csrss.exe", "lsass.exe", "userinit.exe", "dllhost.exe",
          "sihost.exe", "runtimebroker.exe", "wmiprvse.exe", "conhost.exe"}
LOLBIN = {"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe",
          "regasm.exe", "regsvcs.exe", "wmic.exe", "msiexec.exe", "cmstp.exe", "mavinject.exe",
          "forfiles.exe", "esentutl.exe"}
ADMIN = {"net.exe", "net1.exe", "whoami.exe", "schtasks.exe", "sc.exe", "reg.exe", "netsh.exe",
         "vssadmin.exe", "tasklist.exe", "taskkill.exe", "nltest.exe", "ipconfig.exe",
         "systeminfo.exe", "at.exe", "bcdedit.exe", "wbadmin.exe"}
CATS = ["none", "office", "shell", "script_host", "browser", "system", "lolbin", "admin_tool", "other"]
SYS_BINS = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "wininit.exe",
            "smss.exe", "explorer.exe", "taskhostw.exe", "cmd.exe", "powershell.exe", "rundll32.exe",
            "regsvr32.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe", "spoolsv.exe", "sihost.exe",
            "runtimebroker.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe"}
_SR = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\")
PROTECTED = (_SR + "\\system32\\", _SR + "\\syswow64\\", _SR + "\\winsxs\\")


def category(name):
    if not name:
        return "none"
    for cat, st in (("office", OFFICE), ("shell", SHELL), ("script_host", SCRIPT),
                    ("browser", BROWSER), ("system", SYSTEM), ("lolbin", LOLBIN),
                    ("admin_tool", ADMIN)):
        if name in st:
            return cat
    return "other"


def wrong_path_system_binary(path):
    n = base_of(path)
    if n not in SYS_BINS or not path:
        return 0
    ok = path.startswith(PROTECTED) or (n in {"explorer.exe"} and os.path.dirname(path) == _SR)
    return 0 if ok else 1


RE_B64 = re.compile(r"(-enc\b|-encodedcommand|frombase64string|[a-z0-9+/]{80,}={0,2})")
RE_BYPASS = re.compile(r"(executionpolicy\s+bypass|-ep\s+bypass|-exec\s+bypass|-nop\b|-noprofile|"
                       r"-w\s+hidden|-windowstyle\s+hidden|-noni\b)")
RE_DL = re.compile(r"(https?://|downloadstring|downloadfile|invoke-webrequest|\biwr\b|"
                   r"\bcurl\b|\bwget\b|bitsadmin|urlcache|start-bitstransfer)")
RE_IEX = re.compile(r"(\biex\b|invoke-expression|\[char\]|-join|\[convert\]|\bfromcharcode)")
RE_PERSIST = re.compile(r"(schtasks.*/create|currentversion\\run|reg\s+add.*run|sc\s+create|"
                        r"new-service|startup\\)")
RE_DESTRUCT = re.compile(r"(delete\s+shadows|shadowcopy.*delete|recoveryenabled\s+no|wbadmin\s+delete|"
                         r"cipher\s+/w|wevtutil\s+cl|clear-eventlog|vssadmin.*resize)")
RE_TEMP = re.compile(r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp)")
RE_USERW = re.compile(r"(\\users\\|\\programdata\\|\\windows\\temp\\|\\perflogs\\|\\public\\)")
RE_DOUBLEEXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip)\.(exe|scr|com|bat)$")
RE_RUNKEY = re.compile(r"(\\currentversion\\run|\\currentversion\\policies\\explorer\\run|"
                       r"image file execution options|\\winlogon\\(shell|userinit)|\\services\\[^\\]+\\imagepath|"
                       r"\\currentversion\\windows\\load)")
RE_DROP = re.compile(r"\.(exe|dll|bat|ps1|vbs|js|scr|cmd|hta|jar|lnk)$")
RE_SPLUNK = re.compile(r"(splunk|streamfwd)")
SUSP_PORTS = {4444, 5555, 6666, 1337, 31337, 8888, 9001, 4443, 1234, 12345, 6667, 2222, 3333}
WEB_PORTS = {80, 443, 8080, 8443}
HIGH_ACCESS = {"0x1fffff", "0x1410", "0x1010", "0x1438", "0x143a", "0x1f3fff", "0x1f0fff"}


def build_feature_names():
    n = []
    n += [f"cnt_eid_{i}" for i in range(1, 24)] + ["win_len_frac"]
    n += ["has_creation_row", "cmd_len_log", "cmd_len_gt_200", "has_base64", "has_powershell_bypass",
          "has_http_download", "has_ps_obfuscation", "has_persistence_cmd", "has_destructive_cmd",
          "cmd_has_temp_path"]
    n += ["is_executing_from_temp", "is_from_user_writable", "is_from_downloads", "is_from_appdata",
          "is_system_binary_wrong_path", "has_double_extension", "ext_tmp", "ext_scr_com",
          "name_entropy", "name_digit_ratio"]
    n += [f"child_{c}" for c in CATS] + [f"parent_{c}" for c in CATS]
    n += ["office_spawns_exec", "browser_spawns_exec", "shell_spawns_shell", "system_spawns_exec",
          "parent_missing", "parent_in_user_writable"]
    n += ["integ_system", "integ_high", "integ_medium", "integ_low", "integ_unknown"]
    n += ["net_cnt_log", "net_frac_external", "net_unique_dst_log", "net_has_susp_port",
          "net_only_web_ports", "net_frac_high_port"]
    n += ["file_cnt_log", "file_frac_temp", "file_exec_drops_log", "reg_cnt_log", "reg_runkey_log",
          "dns_cnt_log", "dns_max_len_log", "dns_has_long_name", "dns_unique_log"]
    n += ["img_cnt_log", "img_frac_unsigned", "img_frac_invalid_sig", "img_userwritable_log",
          "pa_cnt_log", "pa_high_access_log"]
    n += ["dur_log", "med_delta_log", "min_delta_log", "mean_delta_log", "frac_burst_50ms"]
    return n


FEATURES = build_feature_names()


def main():
    self_test()
    # ─────────────── PASS 1: ordering, windows, labels ───────────────
    print(f"[{ts()}] pass 1: reading ProcessGuid/EventID/SystemTime/Label ...")
    meta = pd.read_csv(CSV, usecols=["ProcessGuid", "EventID", "SystemTime", "Label"],
                       dtype=str, low_memory=False)
    total_rows = len(meta)
    meta["row"] = np.arange(total_rows)
    meta = meta[meta.ProcessGuid.notna() & ~meta.ProcessGuid.str.strip().isin(["", "0"])]
    meta["eid"] = pd.to_numeric(meta.EventID, errors="coerce")
    meta["lab"] = pd.to_numeric(meta.Label, errors="coerce")
    meta = meta[meta.eid.between(1, 23) & meta.lab.notna()].copy()
    meta["eid"] = meta.eid.astype(int)
    meta["y"] = (meta.lab != 0).astype(int)
    meta["t"] = pd.to_datetime(meta.SystemTime, errors="coerce")
    meta = meta.sort_values(["ProcessGuid", "t", "row"], na_position="last", kind="mergesort")
    g = meta.groupby("ProcessGuid", sort=False)
    meta["pos"] = g.cumcount()
    meta["n_total"] = g.row.transform("size")
    guid_y = (g.y.mean() > 0.5).astype(int)
    print(f"[{ts()}] rows={len(meta):,} processes={len(guid_y):,}")

    kept_guids = set(meta.loc[meta.n_total >= MIN_LEN, "ProcessGuid"].unique())
    win = meta[(meta.pos < WINDOW) & meta.ProcessGuid.isin(kept_guids)]
    first1 = meta[(meta.eid == 1) & meta.ProcessGuid.isin(kept_guids)].drop_duplicates("ProcessGuid")
    keep_row = np.zeros(total_rows, dtype=bool)
    keep_row[win.row.values] = True
    keep_row[first1.row.values] = True
    first1_rows = set(first1.row.values)
    print(f"[{ts()}] processes with >= {MIN_LEN} events: {len(kept_guids):,}; "
          f"rows needed in pass 2: {int(keep_row.sum()):,}")

    # ─────────────── PASS 2: row-level flags on needed rows only ───────────────
    cols = ["ProcessGuid", "EventID", "Image", "ParentImage", "CommandLine", "IntegrityLevel",
            "DestinationIp", "DestinationPort", "ImageLoaded", "Signed", "SignatureStatus",
            "TargetFilename", "TargetObject", "QueryName", "GrantedAccess"]
    rows_out, p1_out = [], []
    off = 0
    ip_cache = {}

    def is_external(ip):
        if ip in ip_cache:
            return ip_cache[ip]
        try:
            v = int(ipaddress.ip_address(ip.strip("[]")).is_global)
        except Exception:
            v = -1
        ip_cache[ip] = v
        return v

    for chunk in pd.read_csv(CSV, usecols=cols, dtype=str, chunksize=CHUNK, low_memory=False):
        n = len(chunk)
        idx = np.arange(off, off + n)
        off += n
        m = keep_row[idx]
        if not m.any():
            continue
        c = chunk[m].copy()
        c["row"] = idx[m]
        c["eid"] = pd.to_numeric(c.EventID, errors="coerce").fillna(-1).astype(int)
        img = san_series(c.Image)
        par = san_series(c.ParentImage)
        f = pd.DataFrame({"row": c.row.values, "guid": c.ProcessGuid.values, "eid": c.eid.values})
        f["splunk"] = (img.str.contains(RE_SPLUNK) | par.str.contains(RE_SPLUNK)).astype(np.int8).values
        z = lambda: np.zeros(len(c), dtype=np.float32)
        for k in ("net_ext", "net_port", "file_temp", "file_drop", "reg_run", "dns_len",
                  "img_unsigned", "img_invalid", "img_uw", "pa_high"):
            f[k] = z()
        f["net_dst"] = ""
        f["dns_name"] = ""
        e = c.eid.values
        # EventID 3
        m3 = e == 3
        if m3.any():
            ips = c.DestinationIp[m3].fillna("").astype(str)
            f.loc[m3, "net_ext"] = ips.map(is_external).values
            f.loc[m3, "net_dst"] = ips.values
            f.loc[m3, "net_port"] = pd.to_numeric(c.DestinationPort[m3], errors="coerce").fillna(-1).values
        # EventID 11
        m11 = e == 11
        if m11.any():
            fn = san_series(c.TargetFilename[m11])
            f.loc[m11, "file_temp"] = fn.str.contains(RE_TEMP).astype(np.float32).values
            f.loc[m11, "file_drop"] = fn.str.contains(RE_DROP).astype(np.float32).values
        # EventID 12/13/14
        mr = np.isin(e, (12, 13, 14))
        if mr.any():
            to = san_series(c.TargetObject[mr])
            f.loc[mr, "reg_run"] = to.str.contains(RE_RUNKEY).astype(np.float32).values
        # EventID 22
        m22 = e == 22
        if m22.any():
            q = c.QueryName[m22].fillna("").astype(str).str.lower().str.strip()
            f.loc[m22, "dns_len"] = q.str.len().values
            f.loc[m22, "dns_name"] = q.values
        # EventID 7
        m7 = e == 7
        if m7.any():
            sg = c.Signed[m7].fillna("").astype(str).str.lower()
            ss = c.SignatureStatus[m7].fillna("").astype(str).str.lower()
            il = san_series(c.ImageLoaded[m7])
            f.loc[m7, "img_unsigned"] = (sg != "true").astype(np.float32).values
            f.loc[m7, "img_invalid"] = ((ss != "valid") & (ss != "")).astype(np.float32).values
            f.loc[m7, "img_uw"] = il.str.contains(RE_USERW).astype(np.float32).values
        # EventID 10
        m10 = e == 10
        if m10.any():
            ga = c.GrantedAccess[m10].fillna("").astype(str).str.lower()
            f.loc[m10, "pa_high"] = ga.isin(HIGH_ACCESS).astype(np.float32).values
        rows_out.append(f)
        # process-creation row features
        sel = np.array([r in first1_rows for r in c.row.values])
        if sel.any():
            cmd = san_series(c.CommandLine[sel])
            ii = img[sel]
            pp = par[sel]
            p = pd.DataFrame({"guid": c.ProcessGuid[sel].values})
            p["integ"] = c.IntegrityLevel[sel].fillna("").astype(str).str.lower().values
            p["img"] = ii.values
            p["par"] = pp.values
            p["cmd"] = cmd.values
            p1_out.append(p)
        print(f"       ... {off:>9,} rows scanned", end="\r")
    print()
    R = pd.concat(rows_out, ignore_index=True)
    P1 = pd.concat(p1_out, ignore_index=True).drop_duplicates("guid").set_index("guid")
    print(f"[{ts()}] row-flags built: {len(R):,} rows; creation rows: {len(P1):,}")

    # ─────────────── Splunk drop ───────────────
    splunk_guids = set(R.loc[R.splunk == 1, "guid"].unique())
    splunk_guids |= set(P1.index[P1.img.str.contains(RE_SPLUNK) | P1.par.str.contains(RE_SPLUNK)])
    stage_all = pd.Series({gd: guid_y[gd] for gd in kept_guids})
    s_mal = int(stage_all[stage_all.index.isin(splunk_guids)].sum())
    print(f"[{ts()}] SPLUNK drop: {len(splunk_guids & kept_guids)} processes "
          f"({s_mal} labelled malware, {len(splunk_guids & kept_guids) - s_mal} benign)")
    guids = sorted(kept_guids - splunk_guids)
    y_all = guid_y.reindex(guids).values
    print(f"[{ts()}] after drop: {len(guids):,} processes | malware={int(y_all.sum()):,} "
          f"benign={int((1 - y_all).sum()):,}")

    # ─────────────── per-process feature assembly ───────────────
    W = win[win.ProcessGuid.isin(guids)].copy()
    Rw = R[R.row.isin(W.row.values)].set_index("row")
    W = W.join(Rw.drop(columns=["guid", "eid"]), on="row")
    W["net_ext"] = W.net_ext.fillna(0)
    gW = W.groupby("ProcessGuid", sort=False)

    F = pd.DataFrame(index=guids, columns=FEATURES, dtype=np.float64).fillna(0.0)
    # sequences + counts
    seqs = np.zeros((len(guids), WINDOW), dtype=np.int64)
    gi = {gd: i for i, gd in enumerate(guids)}
    cnt = pd.crosstab(W.ProcessGuid, W.eid)
    for eid_ in range(1, 24):
        if eid_ in cnt.columns:
            F.loc[cnt.index, f"cnt_eid_{eid_}"] = np.log1p(cnt[eid_].values)
    nwin = gW.size()
    F.loc[nwin.index, "win_len_frac"] = nwin.values / WINDOW
    for gd, ev in gW.eid:
        seqs[gi[gd], :len(ev)] = ev.values[:WINDOW]

    # network
    N = W[W.eid == 3]
    if len(N):
        gn = N.groupby("ProcessGuid")
        known = N[N.net_ext >= 0]
        F.loc[gn.size().index, "net_cnt_log"] = np.log1p(gn.size().values)
        ext = known.groupby("ProcessGuid").net_ext.apply(lambda s: (s == 1).mean())
        F.loc[ext.index, "net_frac_external"] = ext.values
        F.loc[gn.net_dst.nunique().index, "net_unique_dst_log"] = np.log1p(gn.net_dst.nunique().values)
        F.loc[gn.net_port.apply(lambda s: float(s.isin(SUSP_PORTS).any())).index, "net_has_susp_port"] = \
            gn.net_port.apply(lambda s: float(s.isin(SUSP_PORTS).any())).values
        F.loc[gn.net_port.apply(lambda s: float(s.isin(WEB_PORTS).all())).index, "net_only_web_ports"] = \
            gn.net_port.apply(lambda s: float(s.isin(WEB_PORTS).all())).values
        F.loc[gn.net_port.apply(lambda s: float((s >= 49152).mean())).index, "net_frac_high_port"] = \
            gn.net_port.apply(lambda s: float((s >= 49152).mean())).values
    # file
    Fi = W[W.eid == 11]
    if len(Fi):
        gf = Fi.groupby("ProcessGuid")
        F.loc[gf.size().index, "file_cnt_log"] = np.log1p(gf.size().values)
        F.loc[gf.file_temp.mean().index, "file_frac_temp"] = gf.file_temp.mean().values
        F.loc[gf.file_drop.sum().index, "file_exec_drops_log"] = np.log1p(gf.file_drop.sum().values)
    # registry
    Rg = W[W.eid.isin([12, 13, 14])]
    if len(Rg):
        gr = Rg.groupby("ProcessGuid")
        F.loc[gr.size().index, "reg_cnt_log"] = np.log1p(gr.size().values)
        F.loc[gr.reg_run.sum().index, "reg_runkey_log"] = np.log1p(gr.reg_run.sum().values)
    # dns
    D = W[W.eid == 22]
    if len(D):
        gd_ = D.groupby("ProcessGuid")
        F.loc[gd_.size().index, "dns_cnt_log"] = np.log1p(gd_.size().values)
        F.loc[gd_.dns_len.max().index, "dns_max_len_log"] = np.log1p(gd_.dns_len.max().values)
        F.loc[gd_.dns_len.max().index, "dns_has_long_name"] = (gd_.dns_len.max().values > 40).astype(float)
        F.loc[gd_.dns_name.nunique().index, "dns_unique_log"] = np.log1p(gd_.dns_name.nunique().values)
    # image loads
    L = W[W.eid == 7]
    if len(L):
        gl = L.groupby("ProcessGuid")
        F.loc[gl.size().index, "img_cnt_log"] = np.log1p(gl.size().values)
        F.loc[gl.img_unsigned.mean().index, "img_frac_unsigned"] = gl.img_unsigned.mean().values
        F.loc[gl.img_invalid.mean().index, "img_frac_invalid_sig"] = gl.img_invalid.mean().values
        F.loc[gl.img_uw.sum().index, "img_userwritable_log"] = np.log1p(gl.img_uw.sum().values)
    # process access
    A = W[W.eid == 10]
    if len(A):
        ga = A.groupby("ProcessGuid")
        F.loc[ga.size().index, "pa_cnt_log"] = np.log1p(ga.size().values)
        F.loc[ga.pa_high.sum().index, "pa_high_access_log"] = np.log1p(ga.pa_high.sum().values)
    # timing
    W["dt_ms"] = gW.t.diff().dt.total_seconds() * 1000.0
    dur = (gW.t.max() - gW.t.min()).dt.total_seconds()
    F.loc[dur.index, "dur_log"] = np.log1p(dur.fillna(0).clip(lower=0).values)
    dd = W.dropna(subset=["dt_ms"])
    if len(dd):
        gt = dd.groupby("ProcessGuid").dt_ms
        F.loc[gt.median().index, "med_delta_log"] = np.log1p(gt.median().clip(lower=0).values)
        F.loc[gt.min().index, "min_delta_log"] = np.log1p(gt.min().clip(lower=0).values)
        F.loc[gt.mean().index, "mean_delta_log"] = np.log1p(gt.mean().clip(lower=0).values)
        F.loc[gt.apply(lambda s: (s < 50).mean()).index, "frac_burst_50ms"] = \
            gt.apply(lambda s: (s < 50).mean()).values

    # process-creation features
    P = P1.reindex(guids)
    has = P.img.notna()
    P = P.fillna("")
    F["has_creation_row"] = has.astype(float).values
    cmd, ii, pp = P.cmd, P.img, P.par
    F["cmd_len_log"] = np.log1p(cmd.str.len().values) / 8.0
    F["cmd_len_gt_200"] = (cmd.str.len() > 200).astype(float).values
    F["has_base64"] = cmd.str.contains(RE_B64).astype(float).values
    F["has_powershell_bypass"] = cmd.str.contains(RE_BYPASS).astype(float).values
    F["has_http_download"] = cmd.str.contains(RE_DL).astype(float).values
    F["has_ps_obfuscation"] = cmd.str.contains(RE_IEX).astype(float).values
    F["has_persistence_cmd"] = cmd.str.contains(RE_PERSIST).astype(float).values
    F["has_destructive_cmd"] = cmd.str.contains(RE_DESTRUCT).astype(float).values
    F["cmd_has_temp_path"] = cmd.str.contains(RE_TEMP).astype(float).values
    F["is_executing_from_temp"] = ii.str.contains(RE_TEMP).astype(float).values
    F["is_from_user_writable"] = ii.str.contains(RE_USERW).astype(float).values
    F["is_from_downloads"] = ii.str.contains(r"\\downloads\\", regex=True).astype(float).values
    F["is_from_appdata"] = ii.str.contains(r"\\appdata\\", regex=True).astype(float).values
    F["is_system_binary_wrong_path"] = ii.map(wrong_path_system_binary).astype(float).values
    F["has_double_extension"] = ii.str.contains(RE_DOUBLEEXT).astype(float).values
    F["ext_tmp"] = ii.str.endswith(".tmp").astype(float).values
    F["ext_scr_com"] = (ii.str.endswith(".scr") | ii.str.endswith(".com")).astype(float).values
    stem = ii.map(lambda p: os.path.splitext(base_of(p))[0])
    F["name_entropy"] = stem.map(entropy).values / 4.5
    F["name_digit_ratio"] = stem.map(lambda s: sum(ch.isdigit() for ch in s) / max(1, len(s))).values
    cc, pc = ii.map(lambda p: category(base_of(p)) if p else "none"), \
        pp.map(lambda p: category(base_of(p)) if p else "none")
    for cat in CATS:
        F[f"child_{cat}"] = (cc == cat).astype(float).values
        F[f"parent_{cat}"] = (pc == cat).astype(float).values
    exec_kids = cc.isin(["shell", "script_host", "lolbin", "admin_tool"])
    F["office_spawns_exec"] = ((pc == "office") & exec_kids).astype(float).values
    F["browser_spawns_exec"] = ((pc == "browser") & exec_kids).astype(float).values
    F["shell_spawns_shell"] = ((pc == "shell") & (cc == "shell")).astype(float).values
    F["system_spawns_exec"] = ((pc == "system") & exec_kids).astype(float).values
    F["parent_missing"] = (pp == "").astype(float).values
    F["parent_in_user_writable"] = pp.str.contains(RE_USERW).astype(float).values
    integ = P.integ
    F["integ_system"] = (integ == "system").astype(float).values
    F["integ_high"] = (integ == "high").astype(float).values
    F["integ_medium"] = (integ == "medium").astype(float).values
    F["integ_low"] = (integ == "low").astype(float).values
    F["integ_unknown"] = (~integ.isin(["system", "high", "medium", "low"])).astype(float).values

    F = F[FEATURES].astype(np.float32).fillna(0.0)

    # ─────────────── filter, balance 50/50 (same rule as before) ───────────────
    lens = (seqs != 0).sum(1)
    keep = lens >= MIN_LEN
    gid = np.array(guids)[keep]; seqs = seqs[keep]; Fv = F.values[keep]; y = y_all[keep]
    rng = np.random.RandomState(SEED)
    mal, ben = np.where(y == 1)[0], np.where(y == 0)[0]
    n = min(len(mal), len(ben))
    sel = np.concatenate([rng.choice(mal, n, replace=False), rng.choice(ben, n, replace=False)])
    rng.shuffle(sel)
    gid, seqs, Fv, y = gid[sel], seqs[sel], Fv[sel], y[sel]
    print(f"[{ts()}] BALANCED dataset: {len(y):,} ({int(y.sum())} malware + {int((1 - y).sum())} benign) "
          f"| features={Fv.shape[1]}")

    np.savez_compressed(OUT_NPZ, guid=gid, seq=seqs, feat=Fv, y=y)
    json.dump({"features": FEATURES, "window": WINDOW, "min_len": MIN_LEN, "seed": SEED,
               "splunk_dropped": len(splunk_guids & kept_guids), "splunk_malware_labelled": s_mal,
               "processes_ge3_events": len(kept_guids), "after_drop": len(guids),
               "after_drop_malware": int(y_all.sum()), "after_drop_benign": int((1 - y_all).sum()),
               "balanced_total": int(len(y)), "balanced_each_class": int(n)},
              open(OUT_META, "w", encoding="utf-8"), indent=2)
    print(f"[{ts()}] saved {OUT_NPZ}")


if __name__ == "__main__":
    main()
