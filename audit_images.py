"""
audit_images.py
===============
Data audit: which Image / ParentImage values give away the label (dataset
artifacts such as monitoring agents or lab tooling) rather than behaviour?

Unit of analysis = PROCESS (ProcessGuid), label = majority label of its rows
(same rule as build_balanced_sequences.py). ParentImage is read from the
process's EventID-1 row. Output: data_audit_images.txt
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
import os, re
import pandas as pd
import numpy as np

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
CSV = os.path.join("dataset", "LMD-2023 [1.87M Elements]", "LMD-2023 [1.87M Elements]Checked",
                   "Labelled LMD-2023", "LMD-2023 [1.87M Elements][Labelled]checked.csv")
OUT = os.path.join(BASE, "data_audit_images.txt")
MIN_N = 5            # min processes for an image to be called "pure"
lines = []


def P(s=""):
    print(s)
    lines.append(s)


def basename(p):
    if not isinstance(p, str) or p in ("-", "0", "nan", ""):
        return "<none>"
    return re.split(r"[\\/]", p.strip())[-1].lower()


def folder(p):
    if not isinstance(p, str) or p in ("-", "0", "nan", ""):
        return "<none>"
    parts = re.split(r"[\\/]", p.strip().lower())
    return "\\".join(parts[:-1][:4]) if len(parts) > 1 else "<none>"


df = pd.read_csv(CSV, usecols=["ProcessGuid", "EventID", "Image", "ParentImage", "Label"],
                 dtype=str, low_memory=False)
df = df[df.ProcessGuid.notna() & ~df.ProcessGuid.str.strip().isin(["", "0"])]
df["y"] = pd.to_numeric(df.Label, errors="coerce")
df = df[df.y.notna()]
df["y"] = (df.y != 0).astype(int)
df["eid"] = pd.to_numeric(df.EventID, errors="coerce")
P(f"rows used: {len(df):,}  | distinct processes: {df.ProcessGuid.nunique():,}")

g = df.groupby("ProcessGuid")
proc = pd.DataFrame({
    "y": (g.y.mean() >= 0.5).astype(int),
    "n_events": g.size(),
    "image": g.Image.agg(lambda s: s.dropna().iloc[0] if s.notna().any() else None),
})
p1 = df[df.eid == 1].drop_duplicates("ProcessGuid").set_index("ProcessGuid").ParentImage
proc["parent"] = p1.reindex(proc.index)
proc["img_b"] = proc.image.map(basename)
proc["par_b"] = proc.parent.map(basename)
proc["img_dir"] = proc.image.map(folder)
P(f"processes: {len(proc):,}  malware: {int(proc.y.sum()):,}  benign: {int((1 - proc.y).sum()):,}")


def table(col, title, top=25):
    t = proc.groupby(col).y.agg(["size", "sum"]).rename(columns={"size": "n", "sum": "mal"})
    t["ben"] = t.n - t.mal
    t["mal_pct"] = t.mal / t.n * 100
    P()
    P("=" * 96)
    P(f" {title}")
    P("=" * 96)
    P(f"  {'value':<46}{'procs':>8}{'benign':>9}{'malware':>9}{'%mal':>8}")
    for k, r in t.sort_values("n", ascending=False).head(top).iterrows():
        P(f"  {str(k)[:45]:<46}{int(r.n):>8}{int(r.ben):>9}{int(r.mal):>9}{r.mal_pct:>7.1f}%")
    return t


t_img = table("img_b", "A. IMAGE (executable name) -- 25 most frequent")
t_par = table("par_b", "B. PARENT IMAGE -- 25 most frequent")
t_dir = table("img_dir", "C. IMAGE FOLDER (first 4 path parts) -- 25 most frequent")


def pure_report(t, name):
    big = t[t.n >= MIN_N]
    pm = big[big.mal_pct >= 99]
    pb = big[big.mal_pct <= 1]
    mal_total = int(proc.y.sum())
    ben_total = int((1 - proc.y).sum())
    P()
    P(f"  [{name}] values with >= {MIN_N} processes: {len(big)}")
    P(f"     100%-malware values : {len(pm)}  -> cover {int(pm.mal.sum())} / {mal_total} "
      f"malware processes ({pm.mal.sum() / mal_total * 100:.1f}%)")
    P(f"     100%-benign values  : {len(pb)}  -> cover {int(pb.ben.sum())} / {ben_total} "
      f"benign processes ({pb.ben.sum() / ben_total * 100:.1f}%)")
    return pm


P()
P("=" * 96)
P(" D. LABEL-LEAK STRENGTH (how pure are the identifiers?)")
P("=" * 96)
pm_img = pure_report(t_img, "Image")
pm_par = pure_report(t_par[t_par.index != "<none>"], "ParentImage")
pure_report(t_dir, "ImageFolder")

# lookup-only classifier: predict majority label of the value (in-sample upper bound)
for col, nm in (("img_b", "Image name"), ("par_b", "Parent name"), ("img_dir", "Image folder")):
    t = proc.groupby(col).y.agg(["size", "sum"])
    correct = np.maximum(t["sum"], t["size"] - t["sum"]).sum()
    P(f"  Predicting label from {nm:<13} ONLY: {correct / len(proc) * 100:.1f}% accuracy "
      f"(majority baseline {max(proc.y.mean(), 1 - proc.y.mean()) * 100:.1f}%)")

P()
P("=" * 96)
P(" E. SUSPECTED LAB / MONITORING-AGENT ARTIFACTS (name or folder keyword match)")
P("=" * 96)
KEYWORDS = ["splunk", "sysmon", "psexe", "winlogbeat", "filebeat", "ansible", "nxlog", "osquery",
            "velociraptor", "sentinel", "carbonblack", "crowdstrike", "wazuh", "ossec", "atomic",
            "caldera", "sandcat", "powershell_ise", "vmtools", "vmware", "virtualbox", "trustedinstaller",
            "msmpeng", "mpcmdrun", "wmiprvse", "wsmprovhost", "winrm"]
P(f"  {'keyword':<18}{'procs':>8}{'benign':>9}{'malware':>9}{'%mal':>8}   (matched in image path or parent)")
txt = (proc.image.fillna("").str.lower() + "|" + proc.parent.fillna("").str.lower())
for kw in KEYWORDS:
    m = txt.str.contains(kw, regex=False)
    if m.sum() == 0:
        continue
    n = int(m.sum()); mal = int(proc.y[m].sum())
    P(f"  {kw:<18}{n:>8}{n - mal:>9}{mal:>9}{mal / n * 100:>7.1f}%")

P()
P("=" * 96)
P(" F. TOP-25 PURE-MALWARE and PURE-BENIGN executables by volume (n >= %d)" % MIN_N)
P("=" * 96)
big = t_img[t_img.n >= MIN_N]
for title, sel in (("pure MALWARE", big[big.mal_pct >= 99]), ("pure BENIGN", big[big.mal_pct <= 1])):
    P(f"  -- {title} --")
    for k, r in sel.sort_values("n", ascending=False).head(25).iterrows():
        P(f"     {k[:44]:<46}{int(r.n):>7} procs")

P()
P(f"Folder-level view: malware procs whose Image lives under 'splunkuniversalforwarder': "
  f"{int(proc.y[proc.image.fillna('').str.lower().str.contains('splunk')].sum())} "
  f"of {int(proc.y.sum())} malware processes total")
open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\nSaved ->", OUT)
