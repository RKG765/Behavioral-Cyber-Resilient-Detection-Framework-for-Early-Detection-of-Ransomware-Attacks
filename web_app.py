"""
web_app.py
==========
Telltale -- Real-Time SOC Web Application
High-performance FastAPI backend with WebSockets for real-time, zero-refresh
endpoint telemetry, hardware monitoring, agent/server subprocess management,
and interactive threat remediation.

Features:
  - Asynchronous WebSockets (/ws): Real-time hardware & event streaming without page refreshes.
  - Subprocess Management: Start, stop, and monitor agent.py and server.py.
  - Interactive Attack Simulation: Dispatches synthetic benign, grey-zone, or malware processes
    through Tier-1 ONNX and Tier-2 Cloud Brain, writing events live to agent.log.
  - Restful APIs: Full access to cross-validation metrics, XAI attributions, and SQLite whitelist.
  - Serves Modern Cyber SOC UI from static/ directory.

Run:
  python web_app.py
"""

import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import re
import json
import time
import asyncio
import sqlite3
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

import psutil
import numpy as np
import onnxruntime as ort
import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# -----------------------------------------------------------------------------
# BASE PATHS & CONFIG
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)

FILE_AGENT_LOG            = os.path.join(BASE_DIR, "agent.log")
FILE_TEST_LOG             = os.path.join(BASE_DIR, "test_agent.log")
FILE_T1_ONNX              = os.path.join(BASE_DIR, "tier1_behavioral.onnx")
FILE_T1_METRICS           = os.path.join(BASE_DIR, "tier1_behavioral_metrics.json")
FILE_T2_METRICS           = os.path.join(BASE_DIR, "tier2_behavioral_metrics.json")
FILE_T2_BEH_THRESHOLD     = os.path.join(BASE_DIR, "tier2_behavioral_threshold.json")
FILE_T2_THRESHOLD         = os.path.join(BASE_DIR, "tier2_threshold.json")
FILE_XAI_SAMPLE           = os.path.join(BASE_DIR, "tier2_xai_sample.json")
FILE_ERROR_ANALYSIS       = os.path.join(BASE_DIR, "tier2_error_analysis.txt")
FILE_WHITELIST_DB         = os.path.join(BASE_DIR, "whitelist.db")
FILE_BEH_DATASET_META     = os.path.join(BASE_DIR, "dataset", "behavioral_dataset_meta.json")

CLOUD_API_URL = "http://127.0.0.1:8000"

# -----------------------------------------------------------------------------
# FASTAPI APP
# -----------------------------------------------------------------------------
app = FastAPI(
    title="EDR Real-Time SOC Command Center",
    description="Live Telltale telemetry, hardware monitoring, and interactive control suite",
    version="3.0.0"
)

# Mount static folder
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Mount how presentation folder
HOW_DIR = os.path.join(BASE_DIR, "how")
os.makedirs(HOW_DIR, exist_ok=True)
app.mount("/how", StaticFiles(directory=HOW_DIR, html=True), name="how")

# -----------------------------------------------------------------------------
# STATE & PROCESS MANAGER
# -----------------------------------------------------------------------------
class ProcessManager:
    """Manages background agent.py and server.py subprocesses cleanly."""
    def __init__(self):
        self.agent_proc: Optional[subprocess.Popen] = None
        self.server_proc: Optional[subprocess.Popen] = None
        self.quarantined_pids: set = set()
        self.blacklisted_ips: set = set()
        self.isolated_host: bool = False
        self.audit_log: List[Dict[str, Any]] = [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "SYSTEM_INIT",
                "target": "SOC Console",
                "details": "Telltale Command Center initialized in real-time mode",
                "analyst": "System"
            }
        ]
        self._init_onnx_session()

    def _init_onnx_session(self):
        try:
            if os.path.exists(FILE_T1_ONNX):
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 1
                opts.inter_op_num_threads = 1
                self.onnx_sess = ort.InferenceSession(FILE_T1_ONNX, opts, providers=["CPUExecutionProvider"])
                self.input_name = self.onnx_sess.get_inputs()[0].name
            else:
                self.onnx_sess = None
        except Exception as e:
            print(f"[WARN] Failed to load ONNX session: {e}")
            self.onnx_sess = None

    def is_server_alive(self) -> Tuple[bool, Dict[str, Any]]:
        try:
            r = requests.get(f"{CLOUD_API_URL}/health", timeout=0.8)
            if r.status_code == 200:
                return True, r.json()
            return False, {"error": f"HTTP {r.status_code}"}
        except Exception:
            return False, {"error": "Cloud server offline"}

    def is_agent_alive(self) -> bool:
        if self.agent_proc and self.agent_proc.poll() is None:
            return True
        # Check system-wide for running agent.py
        for p in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmd = p.info["cmdline"]
                if cmd and any("agent.py" in str(c) for c in cmd):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False

    def start_server(self) -> bool:
        alive, _ = self.is_server_alive()
        if alive:
            return True
        try:
            self.server_proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "server:app", "--port", "8000"],
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2.0)
            alive, _ = self.is_server_alive()
            return alive
        except Exception as e:
            print(f"[ERROR] Start server failed: {e}")
            return False

    def stop_server(self) -> bool:
        if self.server_proc and self.server_proc.poll() is None:
            self.server_proc.terminate()
            self.server_proc = None
            return True
        return False

    def start_agent(self) -> bool:
        if self.is_agent_alive():
            return True
        try:
            self.agent_proc = subprocess.Popen(
                [sys.executable, "agent.py"],
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(1.0)
            return self.is_agent_alive()
        except Exception as e:
            print(f"[ERROR] Start agent failed: {e}")
            return False

    def stop_agent(self) -> bool:
        stopped = False
        if self.agent_proc and self.agent_proc.poll() is None:
            self.agent_proc.terminate()
            self.agent_proc = None
            stopped = True
        # Also clean up any orphan agent.py
        for p in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmd = p.info["cmdline"]
                if cmd and any("agent.py" in str(c) for c in cmd):
                    p.terminate()
                    stopped = True
            except Exception:
                pass
        return stopped

    def score_tier1(self, features: np.ndarray) -> float:
        """Run sub-millisecond local ONNX inference on a (1, 99) feature vector."""
        if self.onnx_sess is None:
            return 0.50
        feat = features.astype(np.float32).reshape(1, 99)
        out = self.onnx_sess.run(None, {self.input_name: feat})[0]
        val = float(out.squeeze())
        # Apply sigmoid if raw logit
        if val < 0.0 or val > 1.0:
            val = float(1.0 / (1.0 + np.exp(-val)))
        return val

    def escalate_tier2(self, proc_name: str, t1_score: float, features: List[float]) -> Dict[str, Any]:
        """POST to Cloud FastAPI /score."""
        payload = {
            "process_name": proc_name,
            "tier1_score": float(t1_score),
            "features": features
        }
        try:
            r = requests.post(f"{CLOUD_API_URL}/score", json=payload, timeout=2.0)
            if r.status_code == 200:
                return r.json()
            return {"verdict": "BENIGN", "confidence": t1_score, "error": f"Cloud returned HTTP {r.status_code}"}
        except Exception as e:
            return {"verdict": "BENIGN", "confidence": t1_score, "error": f"Cloud unreachable: {e}"}

    def append_log_entry(self, level: str, thread: str, msg: str):
        """Append real formatted log line to agent.log."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{now_str} | {level:<8} | {thread:<12} | {msg}\n"
        try:
            with open(FILE_AGENT_LOG, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            print(f"[WARN] Failed to write agent.log: {e}")

mgr = ProcessManager()

# -----------------------------------------------------------------------------
# WEBSOCKET CONNECTION MANAGER
# -----------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, data: Dict[str, Any]):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

ws_manager = ConnectionManager()

# -----------------------------------------------------------------------------
# BACKGROUND WEBSOCKET STREAMING TASK
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(telemetry_broadcaster())

async def telemetry_broadcaster():
    """Pushes real-time hardware metrics and latest events every second."""
    last_line_count = 0
    while True:
        try:
            # 1. Hardware metrics
            cpu = psutil.cpu_percent(interval=None)
            vm = psutil.virtual_memory()
            curr_proc = psutil.Process(os.getpid())
            rss_mb = curr_proc.memory_info().rss / (1024 * 1024)

            # 2. Check statuses
            srv_alive, srv_stats = mgr.is_server_alive()
            agent_alive = mgr.is_agent_alive()

            # 3. Read log delta if modified
            recent_logs = []
            if os.path.exists(FILE_AGENT_LOG):
                try:
                    with open(FILE_AGENT_LOG, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                    curr_count = len(lines)
                    if curr_count != last_line_count:
                        # Grab recent lines
                        delta_lines = lines[-min(25, curr_count):]
                        recent_logs = parse_log_lines(delta_lines)
                        last_line_count = curr_count
                except Exception:
                    pass

            packet = {
                "type": "telemetry_tick",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "hardware": {
                    "cpu_percent": round(cpu, 1),
                    "ram_percent": round(vm.percent, 1),
                    "ram_used_gb": round(vm.used / (1024**3), 2),
                    "ram_total_gb": round(vm.total / (1024**3), 2),
                    "rss_mb": round(rss_mb, 1)
                },
                "status": {
                    "server_online": srv_alive,
                    "server_stats": srv_stats if srv_alive else {},
                    "agent_online": agent_alive,
                    "quarantined_count": len(mgr.quarantined_pids),
                    "blacklisted_count": len(mgr.blacklisted_ips),
                    "host_isolated": mgr.isolated_host
                },
                "recent_logs": recent_logs
            }
            await ws_manager.broadcast(packet)
        except Exception as e:
            print(f"[WARN] Broadcaster error: {e}")

        await asyncio.sleep(1.0)

# -----------------------------------------------------------------------------
# HELPER: PARSE LOG LINES
# -----------------------------------------------------------------------------
def parse_log_lines(lines: List[str]) -> List[Dict[str, Any]]:
    log_pat = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,\.]\d{3})?)\s*\|\s*(?P<level>[A-Z]+)\s*\|\s*(?P<thread>[^|]+)\s*\|\s*(?P<message>.*)$"
    )
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = log_pat.match(line)
        if m:
            ts = m.group("timestamp")
            level = m.group("level").strip()
            thread = m.group("thread").strip()
            msg = m.group("message").strip()
        else:
            ts = "-"
            level = "INFO"
            thread = "-"
            msg = line

        msg_upper = msg.upper()
        verdict = "INFO"
        if "KILLED" in msg_upper or "WOULD KILL" in msg_upper or "[KILL" in msg_upper:
            verdict = "MALWARE KILLED"
        elif "[GREY ZONE]" in msg_upper or "(GREY)" in msg_upper or "GREY ZONE" in msg_upper:
            verdict = "GREY ZONE"
        elif "[TRUSTED]" in msg_upper or "ALLOWED (TRUSTED)" in msg_upper or "ALLOWED (CACHED)" in msg_upper:
            verdict = "TRUSTED / ALLOWED"
        elif "(BENIGN)" in msg_upper or "[BENIGN]" in msg_upper or "BENIGN PID:" in msg_upper:
            verdict = "BENIGN"
        elif "UNKNOWN PID:" in msg_upper:
            verdict = "UNKNOWN (OBSERVED)"
        elif "SKIP (" in msg_upper or "[WATCHDOG]" in msg_upper or "GHOST PROCESS" in msg_upper:
            verdict = "SYSTEM / SKIP"
        elif "[CLOUD OFFLINE]" in msg_upper or "UNREACHABLE" in msg_upper or "ERROR" in level:
            verdict = "OFFLINE / ERROR"
        elif "[SCORE]" in msg_upper or "INFERENCE PID:" in msg_upper:
            verdict = "TIER-1 INFERENCE"

        pid_m = re.search(r"PID:(\d+)", msg, re.I)
        pid = pid_m.group(1) if pid_m else "-"

        proc_m = re.search(r"([a-zA-Z0-9_\-\.]+\.exe)", msg, re.I)
        proc_name = proc_m.group(1) if proc_m else "-"

        score_m = re.search(r"(?:score\s*=\s*|Score:\s*|Tier-1 score\s*=\s*)(0\.\d+)", msg, re.I)
        score = float(score_m.group(1)) if score_m else None

        records.append({
            "timestamp": ts,
            "level": level,
            "verdict": verdict,
            "process": proc_name,
            "pid": pid,
            "score": score,
            "thread": thread,
            "message": msg
        })
    return records

# -----------------------------------------------------------------------------
# REST API ENDPOINTS
# -----------------------------------------------------------------------------
@app.get("/")
def index():
    """Serve the modern SPA front-end."""
    html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse("<h1>SOC Web Application Loading...</h1><p>Please ensure static/index.html is created.</p>")

@app.get("/api/status")
def get_status():
    srv_alive, srv_stats = mgr.is_server_alive()
    agent_alive = mgr.is_agent_alive()
    cpu = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    curr_proc = psutil.Process(os.getpid())
    rss_mb = curr_proc.memory_info().rss / (1024 * 1024)

    return {
        "status": "ok",
        "agent": {
            "running": agent_alive,
            "pid": mgr.agent_proc.pid if mgr.agent_proc else None
        },
        "server": {
            "running": srv_alive,
            "stats": srv_stats if srv_alive else None
        },
        "hardware": {
            "cpu_percent": round(cpu, 1),
            "ram_percent": round(vm.percent, 1),
            "ram_used_gb": round(vm.used / (1024**3), 2),
            "ram_total_gb": round(vm.total / (1024**3), 2),
            "rss_mb": round(rss_mb, 1)
        },
        "mitigations": {
            "quarantined": list(mgr.quarantined_pids),
            "blacklisted_ips": list(mgr.blacklisted_ips),
            "host_isolated": mgr.isolated_host
        }
    }

@app.get("/api/telemetry")
def get_telemetry(max_rows: int = Query(100, ge=10, le=1000), source: str = "agent.log"):
    path = FILE_AGENT_LOG if "agent" in source else FILE_TEST_LOG
    if not os.path.exists(path):
        return {"total": 0, "events": []}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-max_rows:]
        events = parse_log_lines(lines)
        return {
            "total": len(events),
            "source": os.path.basename(path),
            "events": events[::-1]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/metrics")
def get_metrics():
    """Load model metrics from JSON files."""
    t1_data = {}
    t2_data = {}
    t2_thresh = {}
    if os.path.exists(FILE_T1_METRICS):
        with open(FILE_T1_METRICS, "r", encoding="utf-8") as f:
            t1_data = json.load(f)
    if os.path.exists(FILE_T2_METRICS):
        with open(FILE_T2_METRICS, "r", encoding="utf-8") as f:
            t2_data = json.load(f)
    if os.path.exists(FILE_T2_BEH_THRESHOLD):
        with open(FILE_T2_BEH_THRESHOLD, "r", encoding="utf-8") as f:
            t2_thresh = json.load(f)

    return {
        "tier1": t1_data,
        "tier2": t2_data,
        "threshold": t2_thresh
    }

@app.get("/api/xai")
def get_xai():
    """Load XAI threat attribution sample and error ceiling analysis."""
    sample = {}
    if os.path.exists(FILE_XAI_SAMPLE):
        with open(FILE_XAI_SAMPLE, "r", encoding="utf-8") as f:
            sample = json.load(f)

    error_analysis = ""
    if os.path.exists(FILE_ERROR_ANALYSIS):
        with open(FILE_ERROR_ANALYSIS, "r", encoding="utf-8", errors="replace") as f:
            error_analysis = f.read()

    return {
        "sample": sample,
        "error_analysis": error_analysis
    }

@app.get("/api/whitelist")
def query_whitelist(target: str = ""):
    """Read-only query of whitelist.db with live SHA-256 calculation."""
    computed_hash = ""
    target_clean = target.strip()

    if os.path.exists(target_clean):
        try:
            h = hashlib.sha256()
            with open(target_clean, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            computed_hash = h.hexdigest()
        except Exception as e:
            computed_hash = f"Error: {e}"
    elif len(target_clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in target_clean):
        computed_hash = target_clean.lower()

    found = False
    match_entry = None
    all_entries = []

    if os.path.exists(FILE_WHITELIST_DB):
        try:
            conn = sqlite3.connect(f"file:{FILE_WHITELIST_DB}?mode=ro", uri=True)
            cur = conn.cursor()
            if computed_hash:
                cur.execute("SELECT sha256, app_name, added_at FROM trusted_hashes WHERE sha256 = ?", (computed_hash,))
                row = cur.fetchone()
                if row:
                    found = True
                    match_entry = {"sha256": row[0], "app_name": row[1], "added_at": row[2]}

            cur.execute("SELECT sha256, app_name, added_at FROM trusted_hashes LIMIT 30")
            all_entries = [{"sha256": r[0], "app_name": r[1], "added_at": r[2]} for r in cur.fetchall()]
            conn.close()
        except Exception as e:
            print(f"[WARN] Whitelist DB query failed: {e}")

    return {
        "target": target_clean,
        "computed_hash": computed_hash,
        "whitelisted": found,
        "match": match_entry,
        "entries": all_entries
    }

# -----------------------------------------------------------------------------
# CONTROLLER & ACTION APIS
# -----------------------------------------------------------------------------
class ActionRequest(BaseModel):
    action: str
    target: str
    details: Optional[str] = ""

@app.post("/api/action")
def perform_action(req: ActionRequest):
    """Execute simulated security analyst action."""
    action_type = req.action.upper()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if action_type == "QUARANTINE":
        mgr.quarantined_pids.add(req.target)
        mgr.append_log_entry("CRITICAL", "AnalystResp", f"[QUARANTINE] PID:{req.target} process suspended & moved to vault")
    elif action_type == "UNQUARANTINE":
        mgr.quarantined_pids.discard(req.target)
        mgr.append_log_entry("INFO", "AnalystResp", f"[UNQUARANTINE] PID:{req.target} process restored by analyst")
    elif action_type == "BLACKLIST_IP":
        mgr.blacklisted_ips.add(req.target)
        mgr.append_log_entry("WARNING", "AnalystResp", f"[FIREWALL] IP:{req.target} blocked via outbound perimeter rule")
    elif action_type == "UNBLACKLIST_IP":
        mgr.blacklisted_ips.discard(req.target)
    elif action_type == "ISOLATE_HOST":
        mgr.isolated_host = True
        mgr.append_log_entry("CRITICAL", "AnalystResp", f"[HOST ISOLATION] Endpoint network severed (EDR tunnel retained)")
    elif action_type == "RECONNECT_HOST":
        mgr.isolated_host = False
        mgr.append_log_entry("INFO", "AnalystResp", f"[HOST RESTORED] Normal network connectivity resumed")

    mgr.audit_log.append({
        "timestamp": ts,
        "action": action_type,
        "target": req.target,
        "details": req.details,
        "analyst": "SOC Analyst 1 (You)"
    })

    return {
        "status": "success",
        "action": action_type,
        "target": req.target,
        "audit_log": mgr.audit_log[-20:]
    }

@app.get("/api/audit")
def get_audit_log():
    return {"log": mgr.audit_log[::-1]}

@app.post("/api/control/agent/{cmd}")
def control_agent(cmd: str):
    if cmd == "start":
        res = mgr.start_agent()
        return {"status": "started" if res else "failed", "running": mgr.is_agent_alive()}
    elif cmd == "stop":
        res = mgr.stop_agent()
        return {"status": "stopped" if res else "not_running", "running": mgr.is_agent_alive()}
    raise HTTPException(status_code=400, detail="Invalid command")

@app.post("/api/control/server/{cmd}")
def control_server(cmd: str):
    if cmd == "start":
        res = mgr.start_server()
        return {"status": "started" if res else "failed", "running": mgr.is_server_alive()[0]}
    elif cmd == "stop":
        res = mgr.stop_server()
        return {"status": "stopped" if res else "not_running", "running": mgr.is_server_alive()[0]}
    raise HTTPException(status_code=400, detail="Invalid command")

class SimulateRequest(BaseModel):
    scenario: str = "grey_zone"   # benign, grey_zone, malware
    process_name: Optional[str] = None

@app.post("/api/simulate")
def simulate_process_event(req: SimulateRequest):
    """
    Simulates a live process launch event:
      1. Generates 99 behavioral features tailored to the scenario.
      2. Runs Tier-1 local ONNX inference.
      3. If Grey Zone (0.10 - 0.90), escalates via REST POST to Cloud Tier-2 (server.py).
      4. Appends realistic structured log entries to agent.log.
    """
    scenario = req.scenario.lower()
    pid = int(np.random.randint(100000, 290000))

    if scenario == "benign":
        proc = req.process_name or "notepad_custom.exe"
        features = np.random.uniform(0.0, 0.05, size=99).astype(np.float32)
        features[23] = 0.9  # window frac
    elif scenario == "malware":
        proc = req.process_name or "ransomware_dropper.exe"
        features = np.random.uniform(0.5, 0.95, size=99).astype(np.float32)
        features[6] = 48.0   # ImageLoad count
        features[27] = 1.0   # has_base64
        features[34] = 1.0   # is_executing_from_temp
    else:  # grey_zone
        proc = req.process_name or "unknown_admin_tool.exe"
        features = np.random.uniform(0.15, 0.65, size=99).astype(np.float32)
        features[26] = 1.0   # cmd_len_gt_200

    # 1. Tier 1 ONNX Evaluation
    t_start = time.perf_counter()
    t1_score = mgr.score_tier1(features)
    t1_ms = (time.perf_counter() - t_start) * 1000

    escalated = False
    cloud_result = {}
    final_verdict = "ALLOW"

    # Log initial observation
    mgr.append_log_entry("INFO", "Worker_0", f"UNKNOWN PID:{pid} {proc} (unsigned_or_unknown) -- monitoring behavior for 30s")
    mgr.append_log_entry("INFO", "BehaviorMon", f"[SCORE]  {proc} PID:{pid}  Tier-1 score={t1_score:.4f}  ({'benign' if t1_score <= 0.1 else ('kill' if t1_score >= 0.9 else 'grey')})")

    # 2. Routing Logic
    if t1_score <= 0.10:
        final_verdict = "ALLOW"
        mgr.append_log_entry("INFO", "BehaviorMon", f"[BENIGN]  {proc} PID:{pid} -- Tier-1 score={t1_score:.4f} <= 0.10 (Allowed)")
    elif t1_score >= 0.90:
        final_verdict = "LOCAL_KILL"
        mgr.append_log_entry("CRITICAL", "BehaviorMon", f"[MALWARE KILLED]  {proc} PID:{pid} -- score={t1_score:.4f} >= 0.90 (Local Termination)")
    else:
        # Grey Zone -> Escalate to Cloud Tier 2
        escalated = True
        mgr.append_log_entry("WARNING", "BehaviorMon", f"[GREY ZONE]  {proc} escalated to Cloud (Score: {t1_score:.2f}) PID:{pid}")
        cloud_result = mgr.escalate_tier2(proc, t1_score, features.tolist())
        cloud_verdict = cloud_result.get("verdict", "BENIGN")

        if cloud_verdict == "KILL":
            final_verdict = "CLOUD_KILL"
            mgr.append_log_entry("CRITICAL", "CloudVerdict", f"[CLOUD VERDICT]  {proc} KILLED by Tier-2 Cloud ResNet (Score: {cloud_result.get('confidence', 0):.4f}) PID:{pid}")
        else:
            final_verdict = "CLOUD_BENIGN"
            mgr.append_log_entry("INFO", "CloudVerdict", f"[CLOUD VERDICT]  {proc} ALLOWED by Tier-2 Cloud ResNet (Score: {cloud_result.get('confidence', 0):.4f}) PID:{pid}")

    return {
        "scenario": scenario,
        "process_name": proc,
        "pid": pid,
        "tier1_score": round(t1_score, 4),
        "tier1_latency_ms": round(t1_ms, 2),
        "escalated_to_tier2": escalated,
        "cloud_response": cloud_result,
        "final_verdict": final_verdict
    }

# -----------------------------------------------------------------------------
# WEBSOCKET ENDPOINT
# -----------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Client can send ping or commands
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# -----------------------------------------------------------------------------
# MAIN ENTRYPOINT
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    print("=" * 65)
    print("  TELLTALE -- REAL-TIME SOC COMMAND CENTER")
    # The portal can start/stop the agent and has no authentication, so it
    # listens on localhost only. Set EDR_WEB_HOST=0.0.0.0 to expose it (trusted LAN only).
    host = os.environ.get("EDR_WEB_HOST", "127.0.0.1")
    print(f"  Open: http://{'127.0.0.1' if host == '0.0.0.0' else host}:5050/how/")
    print("=" * 65)
    uvicorn.run("web_app:app", host=host, port=5050, reload=False)
