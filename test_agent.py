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
    def __init__(self, empty=False, simulated=False):
        self.empty, self.is_simulated = empty, simulated
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


def reset_agent_state(extractor=None, engine=None, score=0.0, window=30):
    agent.VERIFIED_PATH_CACHE.clear()
    agent.grey_zone_queue.clear()
    agent.sequence_extractor = extractor or FakeExtractor()
    agent.inference_engine = engine or FakeEngine(score)
    agent.whitelist_db = None
    agent.SELF_PIDS.clear()
    agent.behavior_monitor = agent.BehaviorMonitor()
    agent.MONITOR_WINDOW = window
    agent.MAX_MONITORED = 256


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
def t06_real_system_binary_skipped_by_path():
    """cmd.exe from real System32 is skipped (path + name)"""
    reset_agent_state()
    p = subprocess.Popen([os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"),
                          "/c", "ping -n 20 127.0.0.1 >nul"])
    SPAWNED.append(p); time.sleep(0.3)
    agent.handle_new_process(p.pid, "cmd.exe")
    assert p.pid not in agent.behavior_monitor.watched()
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
    ex = agent.SequenceExtractor()
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
