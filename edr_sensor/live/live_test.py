"""
live_test.py -- end-to-end check of edr_sensor against REAL Sysmon events.

Safe by design:
  * spawns only harmless workloads (write/delete temp files, one DNS lookup,
    one TCP connect to example.com:443, one HKCU test value created + removed)
  * NEVER kills or suspends anything -- it only reads features and scores them
  * cleans up everything it creates

Needs: Sysmon installed, admin rights (to read the Sysmon channel), edr_sensor built.
Writes a report to live_test_result.txt next to this file.
"""
import os
import sys
import json
import time
import subprocess

import numpy as np
import onnxruntime as ort
import edr_sensor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ONNX = os.path.join(ROOT, "tier1_behavioral.onnx")
REPORT = os.path.join(HERE, "live_test_result.txt")
WORK = os.path.join(os.environ.get("TEMP", HERE), "edr_live_test")

# Harmless PowerShell workload: files, DNS, one outbound TLS connect, an HKCU value.
PS_WORKLOAD = rf"""
$d = '{WORK}'
New-Item -ItemType Directory -Force -Path $d | Out-Null
1..5 | ForEach-Object {{ Set-Content -Path (Join-Path $d "note$_.txt") -Value 'edr live test' }}
try {{ [System.Net.Dns]::GetHostAddresses('example.com') | Out-Null }} catch {{}}
try {{ $c = New-Object System.Net.Sockets.TcpClient; $c.Connect('example.com', 443); $c.Close() }} catch {{}}
New-Item -Path 'HKCU:\Software\EdrLiveTest' -Force | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\EdrLiveTest' -Name 'probe' -Value 1
Remove-Item -Path 'HKCU:\Software\EdrLiveTest' -Recurse -Force
Start-Sleep -Seconds 8
Remove-Item -Recurse -Force $d
"""

CMD_WORKLOAD = f'mkdir "{WORK}_cmd" 2>nul & echo hi> "{WORK}_cmd\\a.txt" & ping -n 9 127.0.0.1 >nul & rmdir /s /q "{WORK}_cmd"'


def main():
    lines = []
    def out(s=""):
        print(s)
        lines.append(s)

    names = edr_sensor.feature_names()
    idx = {n: i for i, n in enumerate(names)}
    sess = ort.InferenceSession(ONNX, providers=["CPUExecutionProvider"])
    inp, outp = sess.get_inputs()[0].name, sess.get_outputs()[0].name

    sensor = edr_sensor.Sensor()
    sensor.start()
    out(f"sensor started on {edr_sensor.DEFAULT_CHANNEL}")
    time.sleep(1)

    procs = {
        "powershell": subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PS_WORKLOAD],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        "cmd": subprocess.Popen(["cmd.exe", "/c", CMD_WORKLOAD],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    }
    out("spawned: " + ", ".join(f"{k} PID {p.pid}" for k, p in procs.items()))

    # Score every 2 s while they run, like the agent's BehaviorMonitor (no enforcement).
    results = {k: {"pid": p.pid, "scores": []} for k, p in procs.items()}
    t0 = time.time()
    while time.time() - t0 < 14:
        time.sleep(2)
        for k, p in procs.items():
            v = sensor.features(p.pid)
            if v is not None:
                x = np.asarray(v, dtype=np.float32).reshape(1, -1)
                results[k]["scores"].append(round(float(sess.run([outp], {inp: x})[0][0][0]), 4))
    for p in procs.values():
        p.wait(timeout=30)

    # Latency of the hot path the agent calls.
    pid = procs["powershell"].pid
    n = 2000
    t = time.perf_counter()
    for _ in range(n):
        sensor.features(pid)
    feat_us = (time.perf_counter() - t) / n * 1e6

    ok = True
    for k, r in results.items():
        v = sensor.features(r["pid"])
        out("")
        out(f"[{k}] PID {r['pid']}  window events={sensor.event_count(r['pid'])}")
        if v is None:
            out("   NO FEATURES (fewer than 3 events captured)")
            ok = False
            continue
        nz = {n_: round(v[i], 4) for n_, i in idx.items() if v[i] != 0.0}
        out("   non-zero features: " + json.dumps(nz))
        out(f"   Tier-1 scores over time: {r['scores']}")
        checks = {
            "has_creation_row": v[idx["has_creation_row"]] == 1.0,
            "file events seen": v[idx["file_cnt_log"]] > 0 or v[idx["cnt_eid_11"]] > 0,
            "child category correct": v[idx["child_shell"]] == 1.0,
        }
        if k == "powershell":
            checks["dns events seen"] = v[idx["dns_cnt_log"]] > 0
            checks["network events seen"] = v[idx["net_cnt_log"]] > 0
            checks["registry events seen"] = v[idx["reg_cnt_log"]] > 0
        for c, passed in checks.items():
            out(f"   {'PASS' if passed else 'FAIL'}  {c}")
            ok &= bool(passed)

    out("")
    out(f"sensor stats: {sensor.stats()}")
    out(f"features() latency: {feat_us:.1f} us/call")
    sensor.stop()
    out(f"RESULT: {'PASS' if ok else 'FAIL'}")
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
