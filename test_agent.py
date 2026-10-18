"""
test_agent.py -- test suite for agent.py v3. All logs -> test_agent.log
Run:  python test_agent.py
"""
import os, sys, time, shutil, subprocess, tempfile, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_LOG = os.path.join(HERE, "test_agent.log")
open(TEST_LOG, "w").close()

import logging
import numpy as np
import psutil
import agent

# Route all agent logs to the test log instead of agent.log
agent.logger.removeHandler(agent._file)
agent._file.close()
_th = logging.FileHandler(TEST_LOG, encoding="utf-8")
_th.setLevel(logging.DEBUG)
_th.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(threadName)-12s | %(message)s"))
agent.logger.addHandler(_th)

RESULTS = []
SPAWNED = []


def log(msg):
    agent.logger.info(f"[TEST] {msg}")


def spawn(exe_path=None, args=("-n", "60", "127.0.0.1")):
    exe_path = exe_path or os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE")
    p = subprocess.Popen([exe_path, *args], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    SPAWNED.append(p)
    time.sleep(0.3)
    return p


class FakeEngine:
    def __init__(self, score): self.score = score
    def predict(self, seq): return self.score


class FakeExtractor:
    def __init__(self, empty=False, simulated=False, image=None):
        self.empty, self.is_simulated, self.image = empty, simulated, image
    def creation_image(self, pid):
        return self.image
    def get_sequence(self, pid):
        if self.empty:
            return np.zeros((1, 50), dtype=np.int64)
        s = np.zeros((1, 50), dtype=np.int64); s[0, :5] = [1, 3, 11, 5, 22]
        return s


def test(fn):
    name = fn.__name__
    log(f"--- {name}: {fn.__doc__.strip()}")
    try:
        fn()
        RESULTS.append((name, True, ""))
        log(f"PASS {name}")
    except Exception as e:
        RESULTS.append((name, False, repr(e)))
        agent.logger.error(f"[TEST] FAIL {name}: {e}\n{traceback.format_exc()}")
    return fn


def reset_agent_state(extractor=None, engine=None, score=0.0, window=30, max_watch=None,
                      mode="enforce"):
    agent.VERIFIED_PATH_CACHE.clear()
    agent.grey_zone_queue.clear()
    agent.sequence_extractor = extractor or FakeExtractor()
    agent.inference_engine = engine or FakeEngine(score)
    agent.whitelist_db = None
    agent.SELF_PIDS.clear()
    agent.behavior_monitor = agent.BehaviorMonitor()
    agent.MONITOR_WINDOW = window
    agent.MAX_WATCH = window if max_watch is None else max_watch
    agent.EXIT_SETTLE = 0.2
    agent.MAX_MONITORED = 256
    agent.AGENT_MODE = mode
    agent.CLOUD_API_URL = "http://127.0.0.1:9/score"     # never reach a live Tier-2 from tests


class LogCapture(logging.Handler):
    """Collects agent log messages so tests can assert on verdicts."""
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.msgs = []
    def emit(self, record):
        self.msgs.append(record.getMessage())
    def __enter__(self):
        agent.logger.addHandler(self); return self
    def __exit__(self, *a):
        agent.logger.removeHandler(self)
    def has(self, text):
        return any(text in m for m in self.msgs)


# ───────────────────────── tests ─────────────────────────

@test
def t01_lru_eviction():
    """LRU keeps <= capacity and evicts least-recently-used"""
    c = agent.LRUCache(3)
    for k in "abc": c.add(k)
    assert "a" in c                      # touch a -> b is now oldest
    c.add("d")
    assert len(c) == 3 and "b" not in c and "a" in c and "d" in c
    big = agent.LRUCache(1000)
    for i in range(5000): big.add(i)
    assert len(big) == 1000 and big.evictions == 4000 and 4999 in big and 0 not in big


@test
def t02_fingerprint_changes_when_binary_replaced():
    """(path,mtime,size) fingerprint differs after file swap"""
    d = tempfile.mkdtemp()
    f = os.path.join(d, "chrome.exe")
    open(f, "wb").write(b"original")
    fp1 = agent.file_fingerprint(f)
    open(f, "wb").write(b"MALICIOUS-REPLACEMENT")
    fp2 = agent.file_fingerprint(f)
    assert fp1 != fp2
    # same size, new mtime only
    open(f, "wb").write(b"MALICIOUS-REPLACEMENT"); os.utime(f, (1, 1))
    assert agent.file_fingerprint(f) != fp2
    assert agent.file_fingerprint(os.path.join(d, "missing.exe")) is None
    shutil.rmtree(d)


@test
def t03_protected_path_rules():
    """Safelist is path-based with directory boundary + writable-subdir deny"""
    sr = os.environ["SystemRoot"]
    P = agent.is_protected_system_path
    assert P(os.path.join(sr, "System32", "cmd.exe"))
    assert P(os.path.join(sr, "SYSTEM32", "CMD.EXE"))               # case-insens.
    assert P(os.path.join(sr, "System32", "wbem", "WmiPrvSE.exe"))
    assert P(os.path.join(sr, "explorer.exe"))
    assert not P(os.path.join(sr, "System32Evil", "svchost.exe"))   # boundary
    assert not P(os.path.join(sr, "System32", "..", "Temp", "x.exe"))
    assert not P(os.path.join(sr, "Temp", "svchost.exe"))
    assert not P(os.path.join(sr, "System32", "Tasks", "x.exe"))
    assert not P(r"C:\Users\Public\svchost.exe")
    assert not P(r"C:\Users\x\AppData\Local\Temp\powershell.exe")
    assert not P("") and not P(None)


@test
def t04_signature_and_publisher():
    """Real files: OS catalog binary trusted by path; copy in temp is NOT"""
    sr = os.environ["SystemRoot"]
    ok, why = agent.verify_signature(os.path.join(sr, "System32", "notepad.exe"))
    log(f"notepad.exe -> {ok} {why}"); assert ok
    d = tempfile.mkdtemp()
    cp = os.path.join(d, "notepad.exe")
    shutil.copy(os.path.join(sr, "System32", "notepad.exe"), cp)
    ok2, why2 = agent.verify_signature(cp)
    log(f"temp copy of notepad.exe -> {ok2} {why2}"); assert not ok2
    unsigned = os.path.join(d, "evil.exe"); open(unsigned, "wb").write(b"MZ" + b"\0" * 100)
    ok3, why3 = agent.verify_signature(unsigned)
    log(f"unsigned file -> {ok3} {why3}"); assert not ok3
    shutil.rmtree(d)
    # find a real third-party-signed exe (Edge/Chrome) to prove publisher extraction
    cands = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
             r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
             r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]
    for c in cands:
        if os.path.exists(c):
            valid, org = agent._win_verify_trust(c)
            ok4, why4 = agent.verify_signature(c)
            log(f"{c} -> valid={valid} signer={org} trusted={ok4}")
            assert valid and org and ok4
            break
    else:
        log("no Chrome/Edge installed -- publisher extraction on real file skipped")
    py = sys.executable
    v, org = agent._win_verify_trust(py)
    log(f"python.exe -> valid={v} signer={org} trusted={agent.verify_signature(py)}")


@test
def t05_masquerade_not_safelisted_by_name():
    """svchost.exe running from a temp dir is analyzed, NOT skipped"""
    reset_agent_state()
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "svchost.exe")
    shutil.copy(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), fake)
    p = spawn(fake)
    agent.handle_new_process(p.pid, "svchost.exe")
    assert p.pid in agent.behavior_monitor.watched(), "masquerading process was skipped!"
    # same for powershell.exe / cmd.exe names
    p2 = spawn(fake)
    agent.handle_new_process(p2.pid, "powershell.exe")
    assert p2.pid in agent.behavior_monitor.watched()
    p.kill(); p2.kill(); time.sleep(0.2); shutil.rmtree(d, ignore_errors=True)


@test
def t06_signed_shell_is_monitored():
    """(#31) Microsoft-signed cmd.exe in System32 is behavior-monitored, not trusted"""
    reset_agent_state()
    p = subprocess.Popen([os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"),
                          "/c", "ping -n 20 127.0.0.1 >nul"])
    SPAWNED.append(p); time.sleep(0.3)
    agent.handle_new_process(p.pid, "cmd.exe")
    assert p.pid in agent.behavior_monitor.watched()
    assert psutil.Process(p.pid).status() != psutil.STATUS_STOPPED
    p.kill()


@test
def t07_process_never_suspended():
    """Unknown process keeps running while observed (Behavioral Paradox)"""
    reset_agent_state()
    d = tempfile.mkdtemp(); f = os.path.join(d, "unknown_tool.exe")
    shutil.copy(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), f)
    p = spawn(f)
    agent.handle_new_process(p.pid, "unknown_tool.exe")
    time.sleep(0.5)
    st = psutil.Process(p.pid).status()
    log(f"status after triage: {st}")
    assert st != psutil.STATUS_STOPPED and p.poll() is None
    assert p.pid in agent.behavior_monitor.watched()
    p.kill(); time.sleep(0.2); shutil.rmtree(d, ignore_errors=True)


@test
def t08_cache_hit_and_invalidation():
    """Trusted binary cached once; modified binary re-verified"""
    reset_agent_state()
    calls = []
    orig = agent.verify_signature
    agent.verify_signature = lambda path: (calls.append(path) or (True, "Signed:TEST"))
    try:
        d = tempfile.mkdtemp(); f = os.path.join(d, "chrome.exe")
        shutil.copy(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), f)
        p = spawn(f)
        agent.handle_new_process(p.pid, "chrome.exe")
        agent.handle_new_process(p.pid, "chrome.exe")
        assert len(calls) == 1, f"expected 1 verification, got {len(calls)}"
        p.kill(); time.sleep(0.3)
        # malware replaces the binary at the same path
        with open(f, "ab") as fh: fh.write(b"X" * 17)
        p2 = spawn(f)
        agent.handle_new_process(p2.pid, "chrome.exe")
        assert len(calls) == 2, "swapped binary hit the cache (bypass!)"
        p2.kill(); time.sleep(0.2); shutil.rmtree(d, ignore_errors=True)
    finally:
        agent.verify_signature = orig


@test
def t09_threat_killed():
    """score >= 0.90 -> process killed"""
    reset_agent_state(score=0.97)
    p = spawn()
    assert agent.behavior_monitor.register(p.pid, "evil.exe", "C:\\evil.exe")
    agent.behavior_monitor.tick()
    time.sleep(0.5)
    assert p.poll() is not None, "threat survived"
    assert p.pid not in agent.behavior_monitor.watched()


@test
def t10_empty_sequence_not_scored_benign():
    """No events -> no verdict, no kill; window end logs 'no data'"""
    reset_agent_state(extractor=FakeExtractor(empty=True), score=0.99, window=0.2)
    p = spawn()
    agent.behavior_monitor.register(p.pid, "quiet.exe", "C:\\quiet.exe")
    agent.behavior_monitor.tick()
    assert p.poll() is None and p.pid in agent.behavior_monitor.watched()
    time.sleep(0.3); agent.behavior_monitor.tick()
    assert p.poll() is None and p.pid not in agent.behavior_monitor.watched()
    assert not agent.grey_zone_queue
    p.kill()


@test
def t11_benign_and_grey_routing():
    """<=0.10 benign forgotten; 0.5 -> grey queue, process alive"""
    reset_agent_state(score=0.02, window=0.2)
    p = spawn(); agent.behavior_monitor.register(p.pid, "ok.exe", "C:\\ok.exe")
    time.sleep(0.3); agent.behavior_monitor.tick()
    assert p.pid not in agent.behavior_monitor.watched() and not agent.grey_zone_queue
    p.kill(); time.sleep(0.2)
    reset_agent_state(score=0.5, window=0.2)
    p = spawn(); agent.behavior_monitor.register(p.pid, "grey.exe", "C:\\grey.exe")
    time.sleep(0.3); agent.behavior_monitor.tick()
    assert len(agent.grey_zone_queue) == 1 and p.poll() is None
    p.kill()


@test
def t12_dry_run_on_simulated_data():
    """Simulated extractor -> would-kill is logged, process survives"""
    reset_agent_state(extractor=FakeExtractor(simulated=True), score=0.99)
    assert not agent.actions_enforced()
    p = spawn(); agent.behavior_monitor.register(p.pid, "x.exe", "C:\\x.exe")
    agent.behavior_monitor.tick(); time.sleep(0.3)
    assert p.poll() is None
    p.kill()


@test
def t13_grey_zone_fail_open_and_closed():
    """Timeout: OPEN leaves running, CLOSED kills"""
    gz = agent.GreyZoneMonitor()
    old = agent.NETWORK_FAIL_POLICY, agent.GREY_ZONE_TIMEOUT
    try:
        agent.GREY_ZONE_TIMEOUT = 1
        for policy, expect_dead in (("OPEN", False), ("CLOSED", True)):
            reset_agent_state(score=0.5)
            agent.NETWORK_FAIL_POLICY = policy
            p = spawn()
            agent.grey_zone_queue.append({"pid": p.pid, "name": "g.exe", "path": "C:\\g.exe",
                                          "score": 0.5, "frozen_at": time.time() - 5})
            gz._check_timeouts()
            time.sleep(0.5)
            assert (p.poll() is not None) == expect_dead, policy
            p.kill()
    finally:
        agent.NETWORK_FAIL_POLICY, agent.GREY_ZONE_TIMEOUT = old


@test
def t14_self_pid_and_ghost_process():
    """Self PID skipped; nonexistent PID handled without exception"""
    reset_agent_state()
    agent.SELF_PIDS.add(os.getpid())
    agent.handle_new_process(os.getpid(), "python.exe")
    assert not agent.behavior_monitor.watched()
    agent.handle_new_process(4_000_000, "ghost.exe")


@test
def t15_monitor_capacity_cap():
    """Monitor refuses to grow past max_watched"""
    reset_agent_state()
    agent.MAX_MONITORED = 1
    m = agent.BehaviorMonitor()
    p1, p2 = spawn(), spawn()
    assert m.register(p1.pid, "a", "a") and not m.register(p2.pid, "b", "b")
    agent.MAX_MONITORED = 256
    p1.kill(); p2.kill()


@test
def t16_custom_whitelist_db():
    """SQLite whitelist trusts by SHA-256, path independent of cache"""
    agent.CustomWhitelist.DB_PATH = os.path.join(tempfile.mkdtemp(), "wl.db")
    wl = agent.CustomWhitelist()
    d = tempfile.mkdtemp(); f = os.path.join(d, "corp.exe"); open(f, "wb").write(b"MZcorp")
    assert not wl.is_whitelisted(f)
    wl.add_hash(f, "corp"); assert wl.is_whitelisted(f)
    open(f, "wb").write(b"MZcorp-tampered"); assert not wl.is_whitelisted(f)
    wl.close(); shutil.rmtree(d)


@test
def t17_real_onnx_model_probability():
    """ONNX model returns probability in [0,1] on random sequences"""
    eng = agent.InferenceEngine(agent.ONNX_MODEL_PATH)
    ex = agent.BehavioralExtractor()
    scores = [eng.predict(ex.get_sequence(1)) for _ in range(50)]
    log(f"50 scores: min={min(scores):.4f} max={max(scores):.4f}")
    assert all(0.0 <= s <= 1.0 for s in scores)


@test
def t18_lru_thread_safety_and_memory_bound():
    """8 threads hammer the cache; size stays bounded"""
    import threading
    c = agent.LRUCache(1000)
    def work(base):
        for i in range(5000): c.add((base, i))
    ts = [threading.Thread(target=work, args=(b,)) for b in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(c) == 1000


@test
def t19_rust_sensor_end_to_end():
    """Sysmon XML -> Rust edr_sensor features -> ONNX score (skipped if not built)"""
    if agent.edr_sensor is None:
        log("edr_sensor not installed -- skipped"); return
    s = agent.edr_sensor.Sensor()
    def xml(eid, ms, extra=""):
        return (f"<Event><System><EventID>{eid}</EventID>"
                f"<TimeCreated SystemTime='2026-10-18T10:00:00.{ms:03d}0000Z'/></System><EventData>"
                f"<Data Name='ProcessGuid'>{{T19}}</Data><Data Name='ProcessId'>4242</Data>{extra}"
                f"</EventData></Event>")
    assert s.ingest_xml(xml(1, 0, "<Data Name='Image'>C:\\Users\\x\\AppData\\Local\\Temp\\a.exe</Data>"))
    assert s.ingest_xml(xml(11, 10, "<Data Name='TargetFilename'>C:\\Temp\\b.exe</Data>"))
    assert s.features(4242) is None                     # < 3 events: never scored (#22)
    assert s.ingest_xml(xml(3, 20, "<Data Name='DestinationIp'>8.8.8.8</Data>"))
    v = np.asarray(s.features(4242), dtype=np.float32).reshape(1, -1)
    assert v.shape == (1, agent.FEATURE_DIM)
    names = agent.edr_sensor.feature_names()
    assert v[0, names.index("is_executing_from_temp")] == 1.0
    assert v[0, names.index("net_frac_external")] == 1.0
    p = agent.InferenceEngine(agent.ONNX_MODEL_PATH).predict(v)
    log(f"live-path score={p:.4f}")
    assert 0.0 <= p <= 1.0
    s.forget(4242)
    assert s.event_count(4242) == 0


def _exit_and_settle(p):
    """Kill the spawned process, then tick through exit detection + settle."""
    p.kill(); p.wait()
    agent.behavior_monitor.tick()                 # notices the exit
    time.sleep(0.3)
    agent.behavior_monitor.tick()                 # final verdict after EXIT_SETTLE


@test
def t20_exited_threat_gets_post_mortem_alert():
    """(#28) process exits mid-window with threat behavior -> CRITICAL post-mortem alert"""
    reset_agent_state(extractor=FakeExtractor(empty=True), score=0.97)
    p = spawn()
    agent.behavior_monitor.register(p.pid, "quick.exe", "C:\\quick.exe")
    agent.behavior_monitor.tick()                 # no data yet -> nothing scored
    agent.sequence_extractor = FakeExtractor()    # late Sysmon events arrive
    with LogCapture() as cap:
        _exit_and_settle(p)
    assert cap.has("[POST-MORTEM THREAT]") and "quick.exe" in " ".join(cap.msgs)
    assert p.pid not in agent.behavior_monitor.watched()


@test
def t21_exited_grey_is_escalated_not_dropped():
    """(#28) short-lived grey-zone process still reaches Tier-2; offline -> logged, never queued for a kill"""
    reset_agent_state(score=0.5)
    p = spawn()
    agent.behavior_monitor.register(p.pid, "brief.exe", "C:\\brief.exe")
    agent.behavior_monitor.tick()
    assert not agent.grey_zone_queue              # still inside its 30s window
    with LogCapture() as cap:
        _exit_and_settle(p)
    assert cap.has("exited, escalated to Cloud")
    assert cap.has("(exited) -- no Tier-2 verdict")
    assert not agent.grey_zone_queue              # its PID may be reused: no timeout kill
    assert p.pid not in agent.behavior_monitor.watched()


@test
def t22_dormant_process_watch_extended():
    """(#27) no behavior by window end -> keep watching; scored once it acts"""
    ex = FakeExtractor(empty=True)
    reset_agent_state(extractor=ex, score=0.02, window=0.2, max_watch=30)
    p = spawn()
    agent.behavior_monitor.register(p.pid, "sleepy.exe", "C:\\sleepy.exe")
    time.sleep(0.3)
    with LogCapture() as cap:
        agent.behavior_monitor.tick()
    assert cap.has("[DORMANT]") and p.pid in agent.behavior_monitor.watched()
    ex.empty = False                              # wakes up and does something
    with LogCapture() as cap:
        agent.behavior_monitor.tick()
    assert cap.has("[BENIGN]") and p.pid not in agent.behavior_monitor.watched()
    p.kill()


@test
def t23_full_window_finalized_early():
    """(#29) once the 50-event window is full the verdict is final before 30s"""
    class FullExtractor(FakeExtractor):
        def is_complete(self, pid): return True
    reset_agent_state(extractor=FullExtractor(), score=0.5, window=30)
    p = spawn()
    agent.behavior_monitor.register(p.pid, "busy.exe", "C:\\busy.exe")
    agent.behavior_monitor.tick()
    assert p.pid not in agent.behavior_monitor.watched()
    assert len(agent.grey_zone_queue) == 1 and p.poll() is None
    p.kill()


@test
def t24_alert_mode_never_kills():
    """(#30) default alert mode: threat is logged CRITICAL, process survives"""
    reset_agent_state(score=0.99, mode="alert")
    assert not agent.actions_enforced()
    p = spawn(); agent.behavior_monitor.register(p.pid, "x.exe", "C:\\x.exe")
    with LogCapture() as cap:
        agent.behavior_monitor.tick()
    time.sleep(0.3)
    assert p.poll() is None and cap.has("[ALERT] THREAT")
    p.kill()


@test
def t25_default_mode_is_alert():
    """(#30) a fresh agent with no EDR_MODE set does not enforce"""
    env = {k: v for k, v in os.environ.items() if k != "EDR_MODE"}
    out = subprocess.run([sys.executable, "-c", "import agent; print(agent.AGENT_MODE)"],
                         cwd=HERE, env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.strip().splitlines()[-1] == "alert", out.stdout + out.stderr


def _dead_pid():
    """PID of a process that has already exited (a 'ghost' by the time triage runs)."""
    p = subprocess.Popen([os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), "-n", "1", "127.0.0.1"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p.wait()
    return p.pid


def _settle_ghosts():
    time.sleep(0.3)
    agent.behavior_monitor.tick()


@test
def t26_ghost_threat_gets_post_mortem_alert():
    """(#32) process exits before triage, threat behavior in Sysmon data -> post-mortem alert"""
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "dropper.exe")
    with open(fake, "wb") as f:
        f.write(b"MZ not a real program")                    # unsigned -> UNKNOWN
    reset_agent_state(extractor=FakeExtractor(image=fake), score=0.97)
    pid = _dead_pid()
    with LogCapture() as cap:
        agent.handle_new_process(pid, "dropper.exe")
        assert pid in agent.behavior_monitor.watched()
        _settle_ghosts()
    assert cap.has("[POST-MORTEM THREAT]") and cap.has("dropper.exe")
    assert pid not in agent.behavior_monitor.watched()
    shutil.rmtree(d, ignore_errors=True)


@test
def t27_ghost_trusted_binary_not_scored():
    """(#32) ghost of a Microsoft-signed, non-abusable binary is triaged as trusted, not scored"""
    ping = os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE")
    reset_agent_state(extractor=FakeExtractor(image=ping), score=0.97)
    pid = _dead_pid()
    with LogCapture() as cap:
        agent.handle_new_process(pid, "PING.EXE")
        _settle_ghosts()
    assert not cap.has("[SCORE]") and not cap.has("THREAT")
    assert pid not in agent.behavior_monitor.watched()


@test
def t28_ghost_with_reused_pid_not_judged():
    """(#32) Sysmon image no longer matches the WMI name (PID reused) -> no verdict"""
    reset_agent_state(extractor=FakeExtractor(image=r"C:\Other\newproc.exe"), score=0.97)
    pid = _dead_pid()
    with LogCapture() as cap:
        agent.handle_new_process(pid, "oldproc.exe")
        _settle_ghosts()
    assert not cap.has("[SCORE]") and cap.has("no longer matches")


@test
def t29_ghost_ignored_on_simulated_data():
    """(#32) without real Sysmon data a ghost is only logged, never judged"""
    reset_agent_state(extractor=FakeExtractor(simulated=True, image=r"C:\x.exe"), score=0.97)
    pid = _dead_pid()
    agent.handle_new_process(pid, "x.exe")
    assert pid not in agent.behavior_monitor.watched()


# ───────────────────────── summary ─────────────────────────
for p in SPAWNED:
    try: p.kill()
    except Exception: pass

passed = sum(1 for _, ok, _ in RESULTS if ok)
log("=" * 50)
for n, ok, err in RESULTS:
    log(f"{'PASS' if ok else 'FAIL'}  {n}  {err}")
log(f"SUMMARY: {passed}/{len(RESULTS)} passed")
print(f"{passed}/{len(RESULTS)} passed -- full log: {TEST_LOG}")
sys.exit(0 if passed == len(RESULTS) else 1)
