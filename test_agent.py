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
    agent.cloud_client = None


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


class _Reply:
    def __init__(self, body, sig=b"", status=200):
        import base64
        self.status_code, self.content, self.text = status, body, body.decode()
        self.headers = {"x-tt-resp-sig": base64.b64encode(sig).decode()}
    def json(self):
        import json
        return json.loads(self.content)


@test
def t30_cloud_client_signs_verifies_and_fails_over():
    """(#33) signed requests, only server-signed replies accepted, primary -> fallback failover"""
    import base64, hashlib, json
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

    dev = ec.generate_private_key(ec.SECP256R1())
    class FakeKey:   # same contract as edr_sensor.DeviceKey: raw r||s over SHA-256
        kind = "software"
        def public_key(self):
            return dev.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
        def sign(self, data):
            r, s = utils.decode_dss_signature(dev.sign(data, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    server = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(server.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    calls = []
    def fake_post(url, data, headers, timeout, **kw):
        calls.append(url)
        if url.startswith("https://primary"):
            raise agent.requests.exceptions.ConnectionError("down")
        msg = "\n".join(("TT1", "POST", "/v1/score", headers["x-tt-device"], headers["x-tt-time"],
                         headers["x-tt-nonce"], hashlib.sha256(data).hexdigest())).encode()
        assert headers["x-amz-content-sha256"] == hashlib.sha256(data).hexdigest()   # CloudFront OAC
        sig = base64.b64decode(headers["x-tt-sig"])   # verify like the Worker / Lambda do
        dev.public_key().verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                int.from_bytes(sig[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
        body = json.dumps({"verdict": "KILL", "nonce": headers["x-tt-nonce"]}).encode()
        return _Reply(body, server.sign(body))

    orig = agent.requests.post
    agent.requests.post = fake_post
    try:
        c = agent.CloudClient(["https://primary", "https://fallback"], "LIC", pub, FakeKey())
        c.registered = True
        assert c.score([0.0] * 99)["verdict"] == "KILL"
        assert calls == ["https://primary/v1/score", "https://fallback/v1/score"], calls
        c.score([0.0] * 99)
        assert calls[-1] == "https://fallback/v1/score" and len(calls) == 3, "fallback first while primary is down"

        forged = ed25519.Ed25519PrivateKey.generate()
        def forged_post(url, data, headers, timeout, **kw):
            body = json.dumps({"verdict": "BENIGN", "nonce": headers["x-tt-nonce"]}).encode()
            return _Reply(body, forged.sign(body))
        agent.requests.post = forged_post
        try:
            c.score([0.0] * 99)
            raise AssertionError("forged reply was accepted")
        except agent.CloudError:
            pass
    finally:
        agent.requests.post = orig


@test
def t31_device_key_signature_verifies():
    """(#33) edr_sensor.DeviceKey (TPM or software) signs in the format the servers verify"""
    if not hasattr(agent.edr_sensor, "DeviceKey"):
        log("edr_sensor.DeviceKey not built -- skipped"); return
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    k = agent.edr_sensor.DeviceKey("TelltaleTestKeyAgent", machine=False)
    try:
        pk, sig = k.public_key(), k.sign(b"TT1 test")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk).verify(
            utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
            b"TT1 test", ec.ECDSA(hashes.SHA256()))
        log(f"device key kind={k.kind}")
    finally:
        k.delete()


def _ask_dirs():
    """Point the agent and the helper at a fresh, private IPC folder."""
    import telltale_helper as h
    d = tempfile.mkdtemp(prefix="tt_ipc_")
    agent.ALERTS_DIR = h.ALERTS_DIR = os.path.join(d, "alerts")
    agent.DECISIONS_DIR = h.DECISIONS_DIR = os.path.join(d, "decisions")
    agent.REPORTS_OUTBOX = os.path.join(d, "reports_outbox.jsonl")
    return h


@test
def t32_ask_mode_waits_for_user_then_closes():
    """(#34) ask mode never closes on its own; Report keeps the alert open; Close closes the app"""
    import json
    reset_agent_state(mode="ask")
    h = _ask_dirs()
    p = spawn()
    proc = psutil.Process(p.pid)
    with open(agent.FEATURE_META_PATH, encoding="utf-8") as f:
        names = json.load(f)["features"]
    vec = np.zeros(99, dtype=np.float32)
    vec[names.index("has_double_extension")] = 1
    agent._enforce_kill(proc, p.pid, "PING.EXE", proc.exe(), "score=0.97", vec)
    time.sleep(0.3)
    assert p.poll() is None, "ask mode must not close the app on its own"
    alerts = h.due_alerts({}, time.time())
    assert len(alerts) == 1 and any("double extension" in r for r in alerts[0]["reasons"]), alerts

    h.decide(alerts[0]["id"], "report")
    agent.DecisionWatcher().check()
    assert os.path.exists(agent.REPORTS_OUTBOX) and p.poll() is None, "report must not close the app"
    assert h.due_alerts({}, time.time()), "alert stays open after a report"

    h.decide(alerts[0]["id"], "close")
    agent.DecisionWatcher().check()
    p.wait(timeout=5)
    assert not h.due_alerts({}, time.time())


@test
def t33_ask_mode_run_anyway_and_forged_decisions():
    """(#34) Run keeps the app; forged ids, unknown choices and a reused PID close nothing"""
    import json
    reset_agent_state(mode="ask")
    h = _ask_dirs()
    p = spawn()
    proc = psutil.Process(p.pid)
    agent._enforce_kill(proc, p.pid, "PING.EXE", proc.exe(), "score=0.95")
    a = h.due_alerts({}, time.time())[0]
    assert a["reasons"] == [], "no features -> no invented reasons"
    assert not h.due_alerts({a["id"]: time.time()}, time.time()), "dismissed alert waits REMIND_S"

    h.decide("f" * 32, "close")          # no such alert
    h.decide(a["id"], "explode")         # unknown choice
    agent.DecisionWatcher().check()
    assert p.poll() is None

    alert_path = os.path.join(agent.ALERTS_DIR, a["id"] + ".json")
    with open(alert_path, encoding="utf-8") as f:
        stale = json.load(f)
    stale["created"] += 100              # as if the PID now belonged to another process
    with open(alert_path, "w", encoding="utf-8") as f:
        json.dump(stale, f)
    h.decide(a["id"], "close")
    agent.DecisionWatcher().check()
    assert p.poll() is None, "a reused PID must never be closed"

    agent._enforce_kill(proc, p.pid, "PING.EXE", proc.exe(), "score=0.95")
    b = h.due_alerts({}, time.time())[0]
    h.decide(b["id"], "run")
    agent.DecisionWatcher().check()
    assert p.poll() is None and not h.due_alerts({}, time.time())


@test
def t34_reports_upload_or_wait_in_outbox():
    """(#34) Send report uploads via the cloud client; offline reports wait and go with the next one"""
    import json
    reset_agent_state(mode="ask")
    _ask_dirs()
    alert = {"name": "x.exe", "path": "", "reason": "score=0.97", "reasons": ["Ran an encoded (base64) command"]}

    assert agent.send_report(alert) is False, "no cloud client configured -> kept"
    class Cloud:
        def __init__(self, fail): self.fail, self.sent = fail, []
        def report(self, body):
            if self.fail: raise agent.CloudUnavailable("offline")
            self.sent.append(body)
    agent.cloud_client = Cloud(fail=True)
    assert agent.send_report(alert) is False
    with open(agent.REPORTS_OUTBOX, encoding="utf-8") as f:
        assert len(f.readlines()) == 2, "both reports wait in the outbox"

    agent.cloud_client = Cloud(fail=False)
    assert agent.send_report(alert) is True
    assert len(agent.cloud_client.sent) == 3 and agent.cloud_client.sent[0]["reasons"] == alert["reasons"]
    with open(agent.REPORTS_OUTBOX, encoding="utf-8") as f:
        assert f.read() == "", "outbox empty once everything is sent"
    agent.cloud_client = None


@test
def t35_signed_update_needs_release_key_newer_version_and_matching_hash():
    """(#36) only a manifest signed by the release key, newer, with a matching installer hash runs"""
    import base64, hashlib, json, subprocess
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    rel = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(rel.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    installer = b"MZ fake installer"
    def manifest(version, sha=hashlib.sha256(installer).hexdigest(), url="https://dl.example/setup.exe"):
        raw = json.dumps({"version": version, "installer": url, "sha256": sha}).encode()
        return raw, base64.b64encode(rel.sign(raw)).decode()

    raw, sig = manifest("9.0.0")
    assert agent.verify_update(raw, sig, pub)["version"] == "9.0.0"
    assert agent.verify_update(raw.replace(b"9.0.0", b"9.0.1"), sig, pub) is None, "edited manifest"
    other = ed25519.Ed25519PrivateKey.generate()
    assert agent.verify_update(raw, base64.b64encode(other.sign(raw)).decode(), pub) is None, "wrong key"
    assert agent.verify_update(*manifest(agent.AGENT_VERSION), pub) is None, "not newer"
    assert agent.verify_update(*manifest("9.0.0", url="http://dl.example/setup.exe"), pub) is None, "plain http"

    served, ran = {}, []
    class R:
        def __init__(self, b): self.content, self.text = b, b.decode(errors="replace")
    orig = (agent.requests.get, subprocess.Popen, agent.UPDATE_URL, agent.UPDATE_PUBKEY)
    agent.requests.get = lambda url, timeout: R(served[url])
    subprocess.Popen = lambda args, **kw: ran.append(args)
    agent.UPDATE_URL, agent.UPDATE_PUBKEY = "https://u.example/latest.json", pub
    try:
        raw, sig = manifest("9.0.0", sha="0" * 64)   # signed, but the download doesn't match
        served.update({agent.UPDATE_URL: raw, agent.UPDATE_URL + ".sig": sig.encode(), "https://dl.example/setup.exe": installer})
        assert agent.UpdateChecker().check() is None and ran == [], "hash mismatch must not run"
        raw, sig = manifest("9.0.0")
        served.update({agent.UPDATE_URL: raw, agent.UPDATE_URL + ".sig": sig.encode()})
        path = agent.UpdateChecker().check()
        assert ran and ran[0][0] == path and "/VERYSILENT" in ran[0], ran
        with open(path, "rb") as f:
            assert f.read() == installer
        os.remove(path)
    finally:
        agent.requests.get, subprocess.Popen, agent.UPDATE_URL, agent.UPDATE_PUBKEY = orig


@test
def t36_release_build_settings_and_pinned_roots():
    """(#35) edr_sensor carries release settings (empty in dev builds); the pinned roots ship with the build"""
    if not hasattr(agent.edr_sensor, "release_config"):
        log("edr_sensor without release_config (old build) -- skipped"); return
    cfg = agent.edr_sensor.release_config()
    assert set(cfg) == {"endpoints", "server_pubkey", "update_url", "update_pubkey"}, cfg
    pem = os.path.join(os.path.dirname(os.path.abspath(agent.__file__)), "packaging", "pinned_roots.pem")
    with open(pem, encoding="utf-8") as f:
        assert f.read().count("BEGIN CERTIFICATE") == 13


@test
def t37_licence_comes_from_a_protected_file():
    """(#35) read_secret returns the stripped file contents, or "" when the file is missing"""
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "licence.key")
    assert agent.read_secret(p) == "", "missing file -> empty"
    with open(p, "w", encoding="utf-8") as f:
        f.write("  HL-ABCDE-12345-FGHJK-67890\r\n")
    assert agent.read_secret(p) == "HL-ABCDE-12345-FGHJK-67890"
    os.remove(p); os.rmdir(d)


@test
def t38_signed_licence_refusal_stops_agent_unsigned_does_not():
    """Deleted/revoked licence: only a server-signed, fresh refusal stops protection and tells the user"""
    import base64, json, shutil, tempfile
    import telltale_helper as h
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    class FakeKey:   # the fake server below doesn't check device signatures (t30 does)
        kind = "software"
        def public_key(self): return b"\x04" + b"\x01" * 64
        def sign(self, data): return b"\x00" * 64
    server, forged = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(server.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    tmp = tempfile.mkdtemp()
    old = (agent.requests.post, agent.ALERTS_DIR, h.ALERTS_DIR)
    agent.ALERTS_DIR = h.ALERTS_DIR = tmp
    status = os.path.join(tmp, agent.LICENCE_STATUS)
    try:
        c = agent.CloudClient(["https://primary"], "LIC", pub, FakeKey())
        c.registered = True
        def reply(make):
            agent.requests.post = lambda url, data, headers, timeout, **kw: make(headers["x-tt-nonce"])
        signed = lambda key, body: (lambda nonce: _Reply(json.dumps({**body, "nonce": nonce}).encode(),
                                                         key.sign(json.dumps({**body, "nonce": nonce}).encode())))

        for label, make in (("unsigned 403", lambda n: _Reply(b'{"error":"revoked"}', b"", 403)),
                            ("forged", signed(forged, {"licence": "revoked"}))):
            reply(make)
            try:
                c.score([0.0] * 99)
                raise AssertionError(f"{label} reply was accepted")
            except agent.CloudError as e:
                assert not isinstance(e, agent.LicenceRevoked), label
            assert not agent.STOP.is_set() and not os.path.exists(status), f"{label} must not stop the agent"

        reply(signed(server, {"licence": "revoked"}))
        try:
            c.score([0.0] * 99)
            raise AssertionError("signed revocation was ignored")
        except agent.LicenceRevoked:
            pass
        assert agent.STOP.is_set(), "a signed revocation stops protection"
        reason, ts = h.licence_notice(None)
        assert reason == "revoked" and h.licence_notice(ts) is None, "the helper shows it once"

        agent.STOP.clear()
        reply(signed(server, {"device_id": c.device_id}))   # licence restored: a normal registration
        c.register()
        assert not os.path.exists(status), "a valid registration clears the notice"
    finally:
        agent.requests.post, agent.ALERTS_DIR, h.ALERTS_DIR = old
        agent.STOP.clear()
        shutil.rmtree(tmp, ignore_errors=True)


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
