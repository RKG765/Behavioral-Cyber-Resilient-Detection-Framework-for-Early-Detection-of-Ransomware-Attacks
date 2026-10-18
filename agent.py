"""
agent.py
========
Telltale -- Tier 1 Endpoint Security Agent
Process Interception -> Suspension -> Inference -> Routing

Monitors all new process creation via WMI, suspends unknown processes,
verifies trust via Authenticode signatures and local whitelists, runs
ONNX inference for threat scoring, and routes based on confidence:
  <= 0.10 -> RESUME (benign)
  >= 0.90 -> KILL   (malware)
  grey    -> flag for Tier-2 cloud (timeout policy OPEN/CLOSED)

v3 -- BEHAVIORAL ANALYSIS (Option B). Unknown processes are NOT suspended
(a frozen process emits no Sysmon events). They run, are observed, and are
killed when score >= THREAT_THRESHOLD.

Production Corrections Applied:
  #1  Self-PID protection
  #2  Critical process safelist -- validated by EXE PATH, not name (#18)
  #3  Admin privilege check at startup
  #4  Executable path resolution via psutil
  #6  Grey zone timeout (30s, configurable)
  #7  Structured logging (RotatingFileHandler)
  #8  Authenticode signatures + publisher match + SQLite custom whitelist
  #9  ThreadPoolExecutor for fast triage
  #10 Ghost process exception matrix at every psutil call
  #11 Fail-Open / Fail-Closed configurable policy
  #12 SequenceExtractor adapter pattern (pluggable Sysmon source)
  #13 Resource Watchdog (self-monitoring background thread)
  #14 Native WinVerifyTrust (no PowerShell fork-bomb)
  #15 Trust cache
  #16 Behavioral Paradox fix: no suspend(); observe -> kill at >= 0.90
  #17 Cache keyed by (path, mtime_ns, size) -- swapped binary misses cache
  #18 Bounded thread-safe LRU cache (1000 entries) -- no RAM leak
  #19 Path-based safelist w/ dir-boundary + writable-subdir deny list
  #20 Publisher allow-list actually enforced (was defined but unused)
  #21 Dedicated BehaviorMonitor thread (workers never block for 30s)
  #22 Empty sequences are never scored ("no data" != "benign")
  #23 Dry-run when sequence data is simulated (no random kills)
  #24 Absolute paths for log/DB/model (CWD-hijack proof)
  #25 WMI watcher timeout so Ctrl+C / shutdown works
  #26 PID-reuse guard before kill; TOCTOU re-stat before caching
  #27 Dormant processes (no behavior yet) watched up to MAX_WATCH, not dropped at 30s
  #28 Processes that exit mid-window still get a verdict (post-mortem alert / Tier-2)
  #29 Window finalized early once the 50-event training window is full
  #30 Alert-only by default; killing requires --mode enforce / EDR_MODE=enforce
  #31 Abusable signed tools (shells, script hosts, LOLBins) are always monitored
  #32 Ghost processes (exited before triage) are judged from their Sysmon events
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import gc
import time
import uuid
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import sqlite3
import logging
import threading
import numpy as np
from collections import OrderedDict
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
import requests                        # Cloud Tier-2 API calls

import wmi
import psutil
import onnxruntime as ort

try:
    import edr_sensor                  # Rust Sysmon feature extractor (optional)
except ImportError:
    edr_sensor = None


# ══════════════════════════════════════════════════════════════
# PHASE 1: CONSTANTS, CONFIG & LOGGING
# ══════════════════════════════════════════════════════════════

# ── Paths (#24): anchored to the agent's own directory, never the CWD ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Model (Tier 1 — Endpoint) ──
ONNX_MODEL_PATH = os.path.join(BASE_DIR, "tier1_behavioral.onnx")
FEATURE_DIM     = 99               # behavioral feature vector length (must match training)
FEATURE_META_PATH = os.path.join(BASE_DIR, "dataset", "behavioral_dataset_meta.json")
MIN_SENSOR_EVENTS = 3              # training MIN_LEN: fewer events are never scored

# ── Cloud API (Tier 2 — server.py) ──
CLOUD_API_URL   = os.environ.get("EDR_CLOUD_URL", "http://127.0.0.1:8000/score")   # Tier-2 FastAPI server

# ── Behavioral monitoring (#16, #21) ──
MONITOR_WINDOW     = 30            # seconds each unknown process is observed
MONITOR_INTERVAL   = 2             # seconds between scoring ticks
MAX_MONITORED      = 256           # hard cap on concurrently watched processes
MAX_WATCH          = 300           # dormant processes (no behavior yet) are watched up to 5 min (#27)
EXIT_SETTLE        = 2             # seconds to let late Sysmon events land after exit (#28)
MAX_GHOSTS         = 512           # cap on pending post-exit verdicts for ghost processes (#32)
# (#23) While BehavioralExtractor returns random data, kills are only logged.
ENFORCE_ON_SIMULATED = False

# (#30) What a THREAT verdict does. 'alert' (default) only logs -- the models have
# a measurable false-positive rate, so killing must be an explicit opt-in:
#   set EDR_MODE=enforce   or   python agent.py --mode enforce
AGENT_MODE = os.environ.get("EDR_MODE", "alert").strip().lower()

# ── Trust cache (#18) ──
TRUST_CACHE_CAPACITY = 1000

# ── Thresholds ──
SAFE_THRESHOLD   = 0.10            # <= 0.10 -> auto-resume
THREAT_THRESHOLD = 0.90            # >= 0.90 -> auto-kill

# ── Threading ──
MAX_WORKERS = 8                    # concurrent process evaluations

# ── Grey Zone ──
GREY_ZONE_TIMEOUT  = 30            # seconds before timeout action
GREY_ZONE_CHECK_INTERVAL = 5       # seconds between queue checks

# ── Fix #11: Network Failure Policy ──────────────────────────
# Controls what happens when grey zone timeout expires without
# a Tier-2 cloud verdict.
#
# "OPEN"   -> Resume the process (user productivity > security)
#             Best for: developer machines, general workstations
#             Risk: a borderline-malicious process runs unchecked
#
# "CLOSED" -> Kill the process (security > user productivity)
#             Best for: finance servers, healthcare systems
#             Risk: legitimate apps get killed on network outages
#
NETWORK_FAIL_POLICY = "OPEN"

# ── Fix #13: Resource Watchdog ──
RAM_THRESHOLD_MB  = 150            # trigger gc.collect() above this
CRITICAL_RAM_MB   = 300            # force exit(75) above this
WATCHDOG_INTERVAL = 60             # seconds between health checks

# ── Fix #2/#19: Critical Process Safelist ────────────────────
# NAMES alone are NOT trusted (malware can call itself svchost.exe).
# A process is skipped only if its name is in this set AND its real
# exe path is inside a protected system directory.
# python.exe was removed: it legitimately lives in user-writable dirs,
# so a name-based pass would be a bypass. The agent itself is covered
# by SELF_PIDS.
CRITICAL_PROCESSES = {
    # Windows kernel / session
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    # Core services
    "svchost.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe",
    # Security
    "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe",
    # Shell / UI
    "explorer.exe", "sihost.exe", "taskhostw.exe",
    "runtimebroker.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchhost.exe",
    "textinputhost.exe", "ctfmon.exe",
    "wmiprvse.exe",
}

# (#31) Signed Windows tools that attackers commonly abuse. A valid Microsoft
# signature says WHO built the binary, not what it is being used for, so these
# are behavior-monitored even when signed / in System32. (Shells were safelisted
# while the agent suspended processes (#14); nothing is suspended since #16.)
# Matched on the real exe basename -- this list only ADDS scrutiny, never trust.
ALWAYS_WATCH = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe", "msiexec.exe",
    "cmstp.exe", "mavinject.exe", "forfiles.exe", "esentutl.exe",
}

# ── Fix #8/#20: Trusted Authenticode Publishers ──────────────
# The signer's Organization (O=) is extracted from the leaf cert and
# must EQUAL one of these (case-insensitive, exact -- no substring,
# so "Google LLC Fake" does not pass). A valid signature from an
# unknown publisher is NOT trusted.
TRUSTED_SIGNERS = {
    "microsoft corporation",
    "google llc",
    "adobe inc.",
    "mozilla corporation",
    "nvidia corporation",
    "intel corporation",
    "apple inc.",
    "valve corp.",
}

# ── Logging Setup ── (#7, #24)
LOG_FILE     = os.path.join(BASE_DIR, "agent.log")
LOG_MAX_MB   = 5
LOG_BACKUPS  = 3

logger = logging.getLogger("EDR_Agent")
logger.setLevel(logging.DEBUG)

# Console handler (INFO and above)
_console = logging.StreamHandler(sys.stdout)
_console.setLevel(logging.INFO)
_console.setFormatter(logging.Formatter(
    "[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
))
logger.addHandler(_console)

# File handler (DEBUG and above, rotating)
_file = RotatingFileHandler(
    LOG_FILE,
    maxBytes=LOG_MAX_MB * 1024 * 1024,
    backupCount=LOG_BACKUPS,
    encoding="utf-8",
)
_file.setLevel(logging.DEBUG)
_file.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(threadName)-12s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))
logger.addHandler(_file)


# ══════════════════════════════════════════════════════════════
# PHASE 2: AUTHENTICODE VERIFICATION MODULE (#8 Layer 1A)
#          Fix #14: Native WinVerifyTrust (no PowerShell spawn)
# ══════════════════════════════════════════════════════════════

# ── WinVerifyTrust ctypes structures ────────────────────────
# These map the C structs from wintrust.h for direct DLL calls.
# No process spawning — pure DLL call, microsecond latency.

_WTD_UI_NONE = 2
_WTD_CHOICE_FILE = 1
_WTD_REVOKE_NONE = 0
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_USE_DEFAULT_OSVER_CHECK = 0x200
_GUID_VERIFY_V2 = uuid.UUID("{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}")

# ── Fix #19: Path-based protection ───────────────────────────────────────────
# Safelist decisions are made on the real exe PATH. All comparisons
# use a normalized, case-folded, symlink-resolved path and a directory
# BOUNDARY (trailing separator) so that "c:\windows\system32evil\x.exe"
# can never match "c:\windows\system32".

def _norm_path(path: str) -> str:
    """Normalize: strip \\\\?\\ prefix, resolve links/8.3, normcase."""
    if not path:
        return ""
    if path.startswith("\\\\?\\"):
        path = path[4:]
    try:
        path = os.path.realpath(path)
    except Exception:
        pass
    return os.path.normcase(os.path.normpath(path))


def _dir_prefix(path: str) -> str:
    return _norm_path(path).rstrip("\\") + "\\"


_SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")

# Executables under these trees are OS-protected (admin-only writable)...
PROTECTED_DIR_PREFIXES = (
    _dir_prefix(os.path.join(_SYSROOT, "System32")),
    _dir_prefix(os.path.join(_SYSROOT, "SysWOW64")),
    _dir_prefix(os.path.join(_SYSROOT, "WinSxS")),
)
# ...except these sub-trees, which unprivileged users/processes can write to.
USER_WRITABLE_PREFIXES = (
    _dir_prefix(os.path.join(_SYSROOT, "Temp")),
    _dir_prefix(os.path.join(_SYSROOT, "Tasks")),
    _dir_prefix(os.path.join(_SYSROOT, "System32", "Tasks")),
    _dir_prefix(os.path.join(_SYSROOT, "System32", "spool")),
    _dir_prefix(os.path.join(_SYSROOT, "System32", "com")),
    _dir_prefix(os.path.join(_SYSROOT, "SysWOW64", "Tasks")),
    _dir_prefix(os.path.join(_SYSROOT, "SysWOW64", "com")),
)
# Files placed directly in %SystemRoot% (explorer.exe, etc.)
_SYSROOT_NORM = _norm_path(_SYSROOT)


def is_protected_system_path(exe_path: str) -> bool:
    """True only if exe_path really lives in a protected Windows folder."""
    p = _norm_path(exe_path)
    if not p:
        return False
    if any(p.startswith(w) for w in USER_WRITABLE_PREFIXES):
        return False
    if os.path.dirname(p) == _SYSROOT_NORM:
        return True
    return any(p.startswith(d) for d in PROTECTED_DIR_PREFIXES)


def file_fingerprint(exe_path: str):
    """
    (normalized_path, mtime_ns, size) or None if the file can't be stat'd.
    (#17) Used as the cache key so a replaced binary never hits the cache.
    """
    try:
        st = os.stat(exe_path)
        return (_norm_path(exe_path), st.st_mtime_ns, st.st_size)
    except OSError:
        return None


# ── Fix #18: Bounded, thread-safe LRU cache ──────────────────────────

class LRUCache:
    """Least-Recently-Used set. Evicts the oldest entry beyond `capacity`."""

    def __init__(self, capacity: int = 1000):
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._data = OrderedDict()
        self._lock = threading.Lock()
        self.evictions = 0

    def __contains__(self, key) -> bool:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return True
            return False

    def add(self, key):
        with self._lock:
            self._data[key] = True
            self._data.move_to_end(key)
            while len(self._data) > self.capacity:
                self._data.popitem(last=False)
                self.evictions += 1

    def discard(self, key):
        with self._lock:
            self._data.pop(key, None)

    def clear(self):
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

_wintrust_dll = ctypes.windll.wintrust


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_uint),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", wt.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_uint),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_uint),
        ("fdwRevocationChecks", ctypes.c_uint),
        ("dwUnionChoice", ctypes.c_uint),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.c_uint),
        ("hWVTStateData", wt.HANDLE),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_uint),
        ("dwUIContext", ctypes.c_uint),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


def _make_guid(uuid_obj):
    """Convert Python uuid.UUID to ctypes GUID struct (mixed-endian)."""
    g = _GUID()
    g.Data1 = uuid_obj.fields[0]
    g.Data2 = uuid_obj.fields[1]
    g.Data3 = uuid_obj.fields[2]
    b = uuid_obj.bytes
    for i in range(8):
        g.Data4[i] = b[8 + i]
    return g


_crypt32_dll = ctypes.windll.crypt32
_wintrust_dll.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
_wintrust_dll.WTHelperProvDataFromStateData.argtypes = [wt.HANDLE]
_wintrust_dll.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
_wintrust_dll.WTHelperGetProvSignerFromChain.argtypes = [
    ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD]
_crypt32_dll.CertGetNameStringW.restype = wt.DWORD
_crypt32_dll.CertGetNameStringW.argtypes = [
    ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p,
    ctypes.c_wchar_p, wt.DWORD]
_CERT_NAME_ATTR_TYPE = 3
_OID_ORGANIZATION = ctypes.c_char_p(b"2.5.4.10")   # szOID_ORGANIZATION_NAME


def _extract_signer_org(state_handle):
    """
    (#20) Read the leaf certificate's Organization (O=) from the open
    WinVerifyTrust state. Returns str or None. Never raises.
    """
    try:
        if not state_handle:
            return None
        prov = _wintrust_dll.WTHelperProvDataFromStateData(state_handle)
        if not prov:
            return None
        sgnr = _wintrust_dll.WTHelperGetProvSignerFromChain(prov, 0, 0, 0)
        if not sgnr:
            return None
        # CRYPT_PROVIDER_SGNR: cbStruct(4) FILETIME(8) csCertChain(4) pasCertChain(ptr @16)
        chain_len = ctypes.c_uint.from_address(sgnr + 12).value
        chain_ptr = ctypes.c_void_p.from_address(sgnr + 16).value
        if chain_len < 1 or not chain_ptr:
            return None
        # CRYPT_PROVIDER_CERT: cbStruct(4) pad pCert(ptr)
        cert_ctx = ctypes.c_void_p.from_address(
            chain_ptr + ctypes.sizeof(ctypes.c_void_p)).value
        if not cert_ctx:
            return None
        buf = ctypes.create_unicode_buffer(256)
        n = _crypt32_dll.CertGetNameStringW(
            cert_ctx, _CERT_NAME_ATTR_TYPE, 0,
            ctypes.cast(_OID_ORGANIZATION, ctypes.c_void_p), buf, 256)
        return buf.value if n > 1 else None
    except Exception:
        return None


def _win_verify_trust(filepath: str) -> tuple:
    """
    Call WinVerifyTrust to check embedded Authenticode signature.
    Returns (is_valid: bool, signer_org: str | None).
    Pure DLL call — no process spawning.
    """
    try:
        file_info = _WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = filepath
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = _WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        trust_data.dwUIChoice = _WTD_UI_NONE
        trust_data.fdwRevocationChecks = _WTD_REVOKE_NONE
        trust_data.dwUnionChoice = _WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = _WTD_STATEACTION_VERIFY
        trust_data.dwProvFlags = _WTD_USE_DEFAULT_OSVER_CHECK

        guid = _make_guid(_GUID_VERIFY_V2)
        result = _wintrust_dll.WinVerifyTrust(
            ctypes.c_void_p(0),
            ctypes.byref(guid),
            ctypes.byref(trust_data),
        )

        signer = None
        if result == 0:
            signer = _extract_signer_org(trust_data.hWVTStateData)

        # Clean up state handle
        trust_data.dwStateAction = _WTD_STATEACTION_CLOSE
        _wintrust_dll.WinVerifyTrust(
            ctypes.c_void_p(0),
            ctypes.byref(guid),
            ctypes.byref(trust_data),
        )

        return (result == 0, signer)  # S_OK = valid signature
    except Exception:
        return (False, None)


def verify_signature(exe_path: str) -> tuple:
    """
    Two-tier Authenticode verification:

    Tier A (Native DLL, ~5-60us): Call WinVerifyTrust directly.
           Catches embedded signatures (explorer.exe, svchost.exe, Chrome, etc.)
           No process spawning — zero fork-bomb risk.

    Tier B (System Path Heuristic): If WinVerifyTrust fails but the exe
           lives in a trusted Windows directory (C:\Windows\System32,
           Program Files), treat it as OS-trusted. This covers catalog-signed
           binaries (notepad.exe, cmd.exe) that WinVerifyTrust can't verify
           without CryptCATAdmin elevation.

    Args:
        exe_path: Full path to the .exe file

    Returns:
        (is_trusted: bool, signer_description: str)
        On any failure, returns (False, "unknown") -- fail-safe to ONNX
    """
    if not exe_path:
        return (False, "no_path")

    # ── Tier A: Native WinVerifyTrust (embedded signature) ──
    # A VALID signature only proves integrity + a chain to a root CA.
    # Trust additionally requires the PUBLISHER to be allow-listed (#20).
    valid, signer = _win_verify_trust(exe_path)
    if valid and signer and signer.strip().lower() in TRUSTED_SIGNERS:
        return (True, f"Signed:{signer}")

    # ── Tier B: Protected system path (catalog-signed OS binaries) ──
    # Windows catalog signatures (notepad.exe etc.) aren't embedded, so
    # WinVerifyTrust(FILE) fails. Trust them only if the real path is in
    # a protected, admin-only Windows folder (boundary-safe, #19).
    if is_protected_system_path(exe_path):
        return (True, f"ProtectedPath:{os.path.dirname(_norm_path(exe_path))}")

    if valid:
        return (False, f"signed_untrusted_publisher:{signer}")
    return (False, "unsigned_or_unknown")


# ══════════════════════════════════════════════════════════════
# PHASE 3: SQLITE CUSTOM WHITELIST (#8 Layer 1B)
# ══════════════════════════════════════════════════════════════

class CustomWhitelist:
    """
    SQLite-based whitelist for company-internal or manually trusted apps.

    Layer 1B: Used when Authenticode check fails (unsigned/unknown signer).
    Admin can manually add SHA-256 hashes for custom applications.

    The database auto-creates on first run with an empty table.
    """

    DB_PATH = os.path.join(BASE_DIR, "whitelist.db")

    def __init__(self):
        self._conn = sqlite3.connect(self.DB_PATH, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the whitelist table if it doesn't exist."""
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_hashes (
                    sha256    TEXT PRIMARY KEY,
                    app_name  TEXT,
                    added_at  TEXT DEFAULT (datetime('now'))
                )
            """)
            self._conn.commit()
        logger.info(f"Whitelist DB initialized: {self.DB_PATH}")

    def is_whitelisted(self, exe_path: str) -> bool:
        """
        Compute SHA-256 of the file and check against the whitelist.

        Returns True if the hash is in the database.
        Returns False on any error (fail-safe to ONNX inference).
        """
        try:
            file_hash = self._compute_sha256(exe_path)
            with self._lock:
                cursor = self._conn.execute(
                    "SELECT 1 FROM trusted_hashes WHERE sha256 = ?",
                    (file_hash,)
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Whitelist check failed for {exe_path}: {e}")
            return False

    @staticmethod
    def _compute_sha256(filepath: str) -> str:
        """Compute SHA-256 hash of a file in 8KB chunks."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def add_hash(self, exe_path: str, app_name: str = ""):
        """Manually add a file's hash to the whitelist (admin action)."""
        file_hash = self._compute_sha256(exe_path)
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO trusted_hashes (sha256, app_name) VALUES (?, ?)",
                (file_hash, app_name)
            )
            self._conn.commit()
        logger.info(f"Whitelisted: {app_name or exe_path} (SHA-256: {file_hash[:16]}...)")

    def close(self):
        """Close the database connection."""
        self._conn.close()


# ══════════════════════════════════════════════════════════════
# PHASE 4: BEHAVIORAL EXTRACTOR — ADAPTER PATTERN (#12)
# ══════════════════════════════════════════════════════════════

class BehavioralExtractor:
    """
    Adapter that produces a (1, 99) float32 behavioral feature vector
    for ONNX inference against tier1_behavioral.onnx.

    Current implementation: Returns SIMULATED random features.
    Future integration:     Extracts real behavioral features from live
                            Sysmon ETW events for the given PID, using
                            the same 99-feature schema produced by
                            build_behavioral_dataset.py.

    The agent ONLY calls extractor.get_sequence(pid). Swap internals
    for real ETW extraction without touching the rest of agent.py.

    Design:
        - Stateless: safe for concurrent use across thread pool
        - Prototype: np.random.rand(1, 99) — uniform [0,1] distribution
        - Same 99-feature schema as training (build_behavioral_dataset.py)
    """

    # (#23) Set to False when backed by real Sysmon ETW data.
    is_simulated = True

    def __init__(self, feature_dim: int = FEATURE_DIM):
        self.feature_dim = feature_dim
        logger.info(
            f"BehavioralExtractor initialized (SIMULATED -- kills are dry-run) "
            f"feature_dim={feature_dim}"
        )

    def get_sequence(self, pid: int) -> np.ndarray:
        """
        Extract or simulate a behavioral feature vector for the given PID.

        Args:
            pid: Process ID (reserved for future real ETW extraction)

        Returns:
            np.ndarray of shape (1, FEATURE_DIM) dtype float32

        TODO: Replace internals with real behavioral extraction:
            1. Query Sysmon ETW for this PID's events (EventIDs 1-23)
            2. Compute aggregate counts (cnt_eid_N), cmd-line patterns,
               path heuristics, network / file / registry / timing stats
               -- exactly as build_behavioral_dataset.py does per-process
            3. Return as (1, 99) float32 ndarray
        """
        # PROTOTYPE: uniform random features in [0, 1]
        return np.random.rand(1, self.feature_dim).astype(np.float32)

    def forget(self, pid: int):
        pass

    def stop(self):
        pass


class SysmonExtractor:
    """
    Real behavioral features from live Sysmon telemetry, via the Rust
    `edr_sensor` extension (build: see edr_sensor/README.md).

    The Rust side subscribes to the Sysmon event log, buffers each process's
    earliest 50 events, and computes the same 99 features as
    build_behavioral_dataset.py (verified by edr_sensor/parity_check.py).
    get_sequence() returns None until a process has MIN_SENSOR_EVENTS events,
    so it is never scored on "no data" (#22).
    """

    is_simulated = False

    def __init__(self, feature_dim: int = FEATURE_DIM):
        if edr_sensor is None:
            raise RuntimeError("edr_sensor extension is not installed")
        if edr_sensor.FEATURE_DIM != feature_dim:
            raise RuntimeError(
                f"edr_sensor produces {edr_sensor.FEATURE_DIM} features, model expects {feature_dim}"
            )
        if os.path.exists(FEATURE_META_PATH):
            with open(FEATURE_META_PATH, encoding="utf-8") as f:
                trained = json.load(f)["features"]
            if edr_sensor.feature_names() != trained:
                raise RuntimeError("edr_sensor feature order differs from the training schema")
        self.sensor = edr_sensor.Sensor()
        self.sensor.start()          # OSError 15007 if Sysmon is not installed
        logger.info(f"SysmonExtractor initialized (LIVE -- channel {edr_sensor.DEFAULT_CHANNEL})")

    def get_sequence(self, pid: int):
        vec = self.sensor.features(pid, MIN_SENSOR_EVENTS)
        if vec is None:
            return None
        return np.asarray(vec, dtype=np.float32).reshape(1, -1)

    def forget(self, pid: int):
        self.sensor.forget(pid)

    def creation_image(self, pid: int):
        """Image path from the process's Sysmon EventID 1, even after it exited (#32)."""
        get = getattr(self.sensor, "creation_image", None)
        return get(pid) if get else None

    def is_complete(self, pid: int) -> bool:
        """The training window (first 50 events) is full -- the vector is final (#29)."""
        return self.sensor.event_count(pid) >= edr_sensor.WINDOW

    def stop(self):
        self.sensor.stop()


def make_extractor():
    """Live Sysmon features when available, otherwise the simulated dry-run (#23)."""
    try:
        return SysmonExtractor()
    except (RuntimeError, OSError) as e:
        logger.warning(f"Live Sysmon features unavailable ({e}) -- falling back to SIMULATED")
        return BehavioralExtractor()


# ══════════════════════════════════════════════════════════════
# PHASE 4 (cont): ONNX INFERENCE ENGINE
# ══════════════════════════════════════════════════════════════

class InferenceEngine:
    """
    ONNX Runtime inference session wrapper.

    Initialized ONCE at startup, reused across all thread pool workers.
    onnxruntime.InferenceSession is thread-safe by design (internal locking).

    The ONNX model outputs probability [0.0, 1.0] because Sigmoid
    was baked into the graph via ModelForExport during training.
    """

    def __init__(self, model_path: str):
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"ONNX model not found: {model_path}\n"
                f"Run train_tier1_behavioral.py first to generate the model."
            )

        # CPU-only for endpoint deployment (no GPU dependency)
        self.session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name
        logger.info(f"ONNX model loaded: {model_path} (CPU inference)")

    def predict(self, features: np.ndarray) -> float:
        """
        Run inference on a behavioral feature vector.

        Args:
            features: np.ndarray of shape (1, 99) dtype float32

        Returns:
            Probability score [0.0, 1.0]
            0.0 = definitely benign, 1.0 = definitely malware
        """
        result = self.session.run(
            [self.output_name],
            {self.input_name: features},
        )
        return float(result[0][0][0])


# ══════════════════════════════════════════════════════════════
# PHASE 5: PROCESS TRIAGE -- THE DECISION ENGINE
#   Option B (#16): NO suspend(). Triage is path/signature based and
#   fast; unknown processes are handed to the BehaviorMonitor.
# ══════════════════════════════════════════════════════════════

# Shared state (populated in main)
SELF_PIDS = set()
grey_zone_queue = []
grey_zone_lock = threading.Lock()

# ── Fix #17/#18: Trust cache ────────────────────────────────
# Bounded LRU of (normalized_path, mtime_ns, size). A replaced/modified
# binary has a different fingerprint, so it can never hit the cache.
VERIFIED_PATH_CACHE = LRUCache(TRUST_CACHE_CAPACITY)

# These are set in main() before any threads start
inference_engine = None
sequence_extractor = None
whitelist_db = None
behavior_monitor = None


def actions_enforced() -> bool:
    """Kills happen only in enforce mode (#30) and only on real sequence data (#23)."""
    if AGENT_MODE != "enforce":
        return False
    if ENFORCE_ON_SIMULATED:
        return True
    return not getattr(sequence_extractor, "is_simulated", True)


def _cache_trusted(path: str, fp_before):
    """Cache only if the file did not change while we were verifying (#26)."""
    if fp_before is not None and file_fingerprint(path) == fp_before:
        VERIFIED_PATH_CACHE.add(fp_before)


def _triage(pid: int, process_name: str, exe_path: str):
    """
    Trust decision for one executable path (steps 3-6 below).
    Returns (verdict, signer): verdict is one of
      "critical"    critical OS process in its protected path -> skip
      "cached"      fingerprint already verified              -> skip
      "trusted"     trusted publisher signature               -> skip
      "whitelisted" custom SHA-256 whitelist                  -> skip
      "watch"       abusable signed tool (#31)                -> monitor
      "unknown"     anything else                             -> monitor
    """
    name_lower = (process_name or "").lower()
    if name_lower in CRITICAL_PROCESSES:
        if is_protected_system_path(exe_path):
            return "critical", ""
        logger.warning(
            f"MASQUERADE? PID:{pid} claims '{process_name}' but runs from "
            f"{exe_path} -- NOT safelisted, will be analyzed"
        )
    if os.path.basename(exe_path).lower() in ALWAYS_WATCH:
        return "watch", ""
    fp = file_fingerprint(exe_path)
    if fp is not None and fp in VERIFIED_PATH_CACHE:
        return "cached", ""
    is_trusted, signer = verify_signature(exe_path)
    if is_trusted:
        _cache_trusted(exe_path, fp)
        return "trusted", signer
    if whitelist_db and whitelist_db.is_whitelisted(exe_path):
        _cache_trusted(exe_path, fp)
        return "whitelisted", ""
    return "unknown", signer


def _can_judge_ghosts() -> bool:
    """Ghost verdicts need real Sysmon data that outlives the process (#32)."""
    return (hasattr(sequence_extractor, "creation_image")
            and not getattr(sequence_extractor, "is_simulated", True))


def handle_new_process(pid: int, process_name: str):
    """
    Fast triage for a newly spawned process (ThreadPoolExecutor worker).

    Decision chain:
      1. Self-PID check                       (#1)
      2. Resolve exe path (no suspend)        (#4, #16)
         -> already exited: post-exit verdict from Sysmon data (#32)
      3. Critical name + protected PATH       (#2, #19)
      3b. Abusable signed tool -> monitor     (#31)
      4. Fingerprint cache (path,mtime,size)  (#17, #18)
      5. Authenticode + publisher             (#8, #20)
      6. Custom whitelist                     (#8)
      7. Otherwise -> BehaviorMonitor         (#16, #21)
    """
    name_lower = process_name.lower() if process_name else ""

    if pid in SELF_PIDS:
        logger.debug(f"SKIP (self) PID:{pid} {process_name}")
        return

    # ── Resolve path WITHOUT suspending ─────────────────────
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
    except psutil.NoSuchProcess:
        if behavior_monitor is not None and _can_judge_ghosts():
            behavior_monitor.register_ghost(pid, process_name)
            logger.debug(f"Ghost process PID:{pid} {process_name} -- exited before triage, "
                         f"judging it from its Sysmon events")
        else:
            logger.debug(f"Ghost process PID:{pid} {process_name} -- already exited")
        return
    except (psutil.AccessDenied, psutil.ZombieProcess):
        if name_lower in CRITICAL_PROCESSES:
            logger.debug(f"SKIP (protected, path unreadable) PID:{pid} {process_name}")
        else:
            logger.warning(f"Cannot resolve path PID:{pid} {process_name} -- not monitorable")
        return
    except Exception as e:
        logger.error(f"Path resolution error PID:{pid} {process_name}: {e}")
        return

    if not exe_path:
        logger.warning(f"Empty exe path PID:{pid} {process_name} -- not monitorable")
        return

    verdict, signer = _triage(pid, process_name, exe_path)
    if verdict == "critical":
        logger.debug(f"SKIP (critical, protected path) PID:{pid} {process_name}")
    elif verdict == "cached":
        logger.debug(f"ALLOWED (cached) PID:{pid} {process_name}")
    elif verdict == "trusted":
        logger.info(f"[TRUSTED]  {process_name} allowed PID:{pid} ({signer[:60]})")
    elif verdict == "whitelisted":
        logger.info(f"ALLOWED (custom whitelist) PID:{pid} {process_name}")
    else:
        if verdict == "watch":
            logger.info(f"[WATCH]    {process_name} PID:{pid} -- signed system tool, "
                        f"monitoring behavior  path={exe_path}")
        else:
            logger.info(
                f"UNKNOWN PID:{pid} {process_name} ({signer}) -- "
                f"monitoring behavior for {MONITOR_WINDOW}s  path={exe_path}"
            )
        if behavior_monitor is not None:
            behavior_monitor.register(pid, process_name, exe_path)


def _safe_kill(proc, pid: int, name: str):
    """Kill a process with ghost/PID-reuse guards (#10, #26)."""
    try:
        if not proc.is_running():       # psutil compares create_time -> PID reuse safe
            logger.debug(f"Kill skipped: PID:{pid} {name} no longer the same process")
            return False
        proc.kill()
        return True
    except psutil.NoSuchProcess:
        logger.debug(f"Kill failed: PID:{pid} {name} already exited")
    except psutil.AccessDenied:
        logger.warning(f"Kill denied: PID:{pid} {name} -- OS-protected")
    except Exception as e:
        logger.error(f"Kill error PID:{pid} {name}: {e}")
    return False


def _enforce_kill(proc, pid, name, path, reason):
    """Kill, or just log in dry-run mode (#23)."""
    if not actions_enforced():
        tag = "ALERT" if AGENT_MODE != "enforce" else "DRY-RUN"
        logger.critical(f"[{tag}] THREAT PID:{pid} {name} -- {reason}  path={path}  "
                        f"(not killed: mode={AGENT_MODE})")
        return False
    ok = _safe_kill(proc, pid, name)
    if ok:
        logger.critical(f"KILLED PID:{pid} {name} -- {reason}  path={path}")
    return ok


# ══════════════════════════════════════════════════════════════
# PHASE 5b: BEHAVIOR MONITOR (#16, #21, #22)
# ══════════════════════════════════════════════════════════════

class BehaviorMonitor:
    """
    One daemon thread scores ALL watched processes every MONITOR_INTERVAL.
    Worker threads only call register() and return immediately.

      score >= THREAT_THRESHOLD -> kill()
      no events yet             -> keep waiting (never scored as benign, #22)
      window over, max <= SAFE  -> benign, forget
      window over, in between   -> grey zone queue (Tier-2)
      window full (50 events)   -> final early: the vector can no longer change (#29)
      no data at window end     -> watch extended up to MAX_WATCH for dormant
                                   processes, then logged (fail-open) (#27)
      process exited            -> final verdict from its buffered behavior after
                                   EXIT_SETTLE: post-mortem alert / Tier-2 (#28)
    """

    def __init__(self):
        self._watch = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def register(self, pid, name, path):
        try:
            created = psutil.Process(pid).create_time()
        except psutil.Error:
            return False
        with self._lock:
            if len(self._watch) >= MAX_MONITORED and pid not in self._watch:
                logger.error(f"Monitor full ({MAX_MONITORED}) -- PID:{pid} {name} NOT watched")
                return False
            self._watch[pid] = {
                "pid": pid, "name": name, "path": path, "created": created,
                "started": time.time(), "max_score": 0.0, "scored": 0,
                "last_seq": None, "exited_at": None, "pid_reused": False,
                "extended": False,
            }
        return True

    def register_ghost(self, pid, name):
        """
        (#32) A process that exited before triage could read its path. Its
        Sysmon events are still buffered, so queue it for a post-exit verdict:
        after EXIT_SETTLE the recorded image path is triaged like any other.
        """
        now = time.time()
        with self._lock:
            if pid in self._watch:
                return False
            if sum(1 for x in self._watch.values() if x.get("ghost")) >= MAX_GHOSTS:
                logger.warning(f"Ghost queue full ({MAX_GHOSTS}) -- PID:{pid} {name} not judged")
                return False
            self._watch[pid] = {
                "pid": pid, "name": name, "path": None, "created": None,
                "started": now, "max_score": 0.0, "scored": 0,
                "last_seq": None, "exited_at": now, "pid_reused": False,
                "extended": False, "ghost": True,
            }
        return True

    def watched(self):
        with self._lock:
            return list(self._watch)

    def monitor(self):
        logger.info(f"Behavior Monitor started (window={MONITOR_WINDOW}s, interval={MONITOR_INTERVAL}s)")
        while not self._stop.wait(MONITOR_INTERVAL):
            try:
                self.tick()
            except Exception as e:
                logger.error(f"Behavior monitor tick error: {e}")

    def _drop(self, pid):
        with self._lock:
            self._watch.pop(pid, None)
        forget = getattr(sequence_extractor, "forget", None)
        if forget:
            forget(pid)

    @staticmethod
    def _live_process(e):
        """(proc, None) while the watched process runs, else (None, pid_was_reused)."""
        try:
            proc = psutil.Process(e["pid"])
            if abs(proc.create_time() - e["created"]) > 1e-3:
                return None, True
            if not proc.is_running():
                return None, False
            return proc, None
        except psutil.Error:
            return None, False

    def _score(self, e, seq):
        """Score one vector; returns the score, or None when there is no data (#22)."""
        if seq is None or not np.any(seq):
            return None
        score = inference_engine.predict(seq)
        e["scored"] += 1
        e["max_score"] = max(e["max_score"], score)
        e["last_seq"] = seq
        logger.info(
            f"[SCORE]  {e['name']} PID:{e['pid']}  Tier-1 score={score:.4f}  "
            f"({'THREAT' if score >= THREAT_THRESHOLD else 'grey' if score > SAFE_THRESHOLD else 'benign'})"
        )
        return score

    @staticmethod
    def _window_complete(pid):
        done = getattr(sequence_extractor, "is_complete", None)
        return bool(done and done(pid))

    def tick(self):
        now = time.time()
        with self._lock:
            entries = list(self._watch.values())
        for e in entries:
            pid, name = e["pid"], e["name"]

            if e["exited_at"] is not None:                      # #28
                if now - e["exited_at"] >= EXIT_SETTLE:
                    if e.get("ghost"):
                        self._finalize_ghost(e)                  # #32
                    else:
                        self._finalize_exited(e)
                    self._drop(pid)
                continue

            proc, reused = self._live_process(e)
            if proc is None:
                e["exited_at"], e["pid_reused"] = now, reused
                logger.debug(f"Monitor: PID:{pid} {name} exited -- final verdict in {EXIT_SETTLE}s")
                continue

            score = self._score(e, sequence_extractor.get_sequence(pid))
            if score is not None and score >= THREAT_THRESHOLD:
                _enforce_kill(proc, pid, name, e["path"],
                              f"score={score:.4f} >= {THREAT_THRESHOLD}")
                self._drop(pid)
                continue

            age = now - e["started"]
            if e["scored"]:
                if age >= MONITOR_WINDOW or self._window_complete(pid):   # #29
                    self._finalize(e)
                    self._drop(pid)
            elif age >= MAX_WATCH:
                self._finalize(e)
                self._drop(pid)
            elif age >= MONITOR_WINDOW and not e["extended"]:          # #27
                e["extended"] = True
                logger.info(
                    f"[DORMANT]    {name} PID:{pid} no behavior in {MONITOR_WINDOW}s "
                    f"-- watching up to {MAX_WATCH}s"
                )

    def _finalize(self, e):
        pid, name, ms = e["pid"], e["name"], e["max_score"]
        if e["scored"] == 0:
            logger.warning(
                f"NO BEHAVIOR DATA PID:{pid} {name} in {MAX_WATCH}s "
                f"-- left running (unverified)"
            )
        elif ms <= SAFE_THRESHOLD:
            logger.info(f"[BENIGN]     {name} allowed (Score: {ms:.2f}) PID:{pid}")
        else:
            logger.warning(
                f"[GREY ZONE]  {name} escalated to Cloud (Score: {ms:.2f}) PID:{pid}"
            )
            self._escalate_to_cloud(e)

    def _finalize_ghost(self, e):
        """(#32) Triage a process that exited before triage, from its Sysmon record."""
        pid, name = e["pid"], e["name"]
        path = sequence_extractor.creation_image(pid)
        if not path:
            logger.debug(f"[GHOST]      {name} PID:{pid} -- no Sysmon creation event, not judged")
            return
        # WMI process names can be truncated (15 chars) -- prefix match. A mismatch
        # means the PID now belongs to another process: judge nothing.
        base = os.path.basename(path).lower()
        if not name or not base.startswith(name.lower()):
            logger.debug(f"[GHOST]      PID:{pid} '{name}' no longer matches {path} -- not judged")
            return
        verdict, _ = _triage(pid, name, path)
        if verdict not in ("watch", "unknown"):
            logger.debug(f"[GHOST]      {name} PID:{pid} exited before triage -- {verdict}")
            return
        e["path"] = path
        logger.debug(f"[GHOST]      {name} PID:{pid} exited before triage -- judging recorded "
                     f"behavior  path={path}")
        self._finalize_exited(e, quiet=True)

    def _finalize_exited(self, e, quiet=False):
        """
        (#28) A process that exits mid-window still gets a verdict. Its buffered
        behavior is scored once more (late Sysmon events included); if the PID was
        already reused, the last vector scored while it ran is used instead.
        quiet: benign / no-data outcomes are logged at DEBUG (ghost processes, #32).
        """
        pid, name = e["pid"], e["name"]
        info = logger.debug if quiet else logger.info
        seq = None if e["pid_reused"] else sequence_extractor.get_sequence(pid)
        if self._score(e, seq) is None and e["last_seq"] is not None:
            self._score(e, e["last_seq"])
        ms = e["max_score"]
        if e["scored"] == 0:
            info(f"[EXITED]     {name} PID:{pid} exited before producing behavior data")
        elif ms >= THREAT_THRESHOLD:
            logger.critical(
                f"[POST-MORTEM THREAT]  {name} PID:{pid} exited before it could be killed "
                f"-- Tier-1 score={ms:.4f}  path={e['path']}  (investigate its children / files)"
            )
        elif ms <= SAFE_THRESHOLD:
            info(f"[BENIGN]     {name} exited, allowed (Score: {ms:.2f}) PID:{pid}")
        else:
            logger.warning(
                f"[GREY ZONE]  {name} exited, escalated to Cloud for a verdict (Score: {ms:.2f}) PID:{pid}"
            )
            self._escalate_to_cloud(e)

    def _escalate_to_cloud(self, e):
        """
        POST the process behavioral features to the Tier-2 Cloud API
        (server.py) and enforce the returned verdict immediately.
        Falls back to grey_zone_queue timeout policy if server unreachable.
        """
        pid, name, path = e["pid"], e["name"], e["path"]
        t1_score = e["max_score"]

        # Get a fresh feature vector for cloud analysis
        # An exited process's PID may be reused -- send the vector it was scored on.
        seq = e.get("last_seq") if e.get("exited_at") else sequence_extractor.get_sequence(pid)
        if seq is None:
            seq = e.get("last_seq")
        if seq is None:
            logger.warning(f"[GREY ZONE]  {name} PID:{pid} -- no features left to escalate")
            return
        features = seq.flatten().tolist()
        payload  = {
            "process_name": name,
            "tier1_score": float(t1_score),
            "features": features,
        }

        try:
            resp = requests.post(CLOUD_API_URL, json=payload, timeout=5)
            resp.raise_for_status()
            data       = resp.json()
            verdict    = data.get("verdict", "UNKNOWN")
            confidence = float(data.get("confidence", 0.0))

            if verdict == "KILL":
                logger.critical(
                    f"[CLOUD VERDICT]  {name} THREAT per Tier-2 "
                    f"(Score: {confidence:.2f})  PID:{pid}  path={path}"
                )
                if e.get("exited_at"):
                    # The PID may already belong to another process -- alert only.
                    logger.critical(
                        f"[POST-MORTEM THREAT]  {name} PID:{pid} had exited -- Tier-2 "
                        f"conf={confidence:.4f}  path={path}  (investigate its children / files)"
                    )
                    return
                try:
                    proc = psutil.Process(pid)
                    if (proc.is_running() and
                            abs(proc.create_time() - e["created"]) <= 1e-3):
                        _enforce_kill(
                            proc, pid, name, path,
                            f"Tier-2 KILL verdict conf={confidence:.4f}"
                        )
                    else:
                        logger.debug(
                            f"Cloud kill skipped: PID:{pid} {name} already exited"
                        )
                except psutil.Error:
                    logger.debug(
                        f"Cloud kill: PID:{pid} {name} no longer running"
                    )
            else:
                logger.info(
                    f"[CLOUD VERDICT]  {name} ALLOWED by Tier-2 "
                    f"(Score: {confidence:.2f})  PID:{pid}"
                )

        except requests.exceptions.ConnectionError:
            if e.get("exited_at"):
                logger.error(f"[CLOUD OFFLINE]  {name} PID:{pid} (exited) -- no Tier-2 verdict, "
                             f"Tier-1 score={t1_score:.4f}  path={path}")
                return
            logger.error(
                f"[CLOUD OFFLINE]  {name} -- server unreachable, "
                f"falling back to timeout policy (policy={NETWORK_FAIL_POLICY})"
            )
            with grey_zone_lock:
                grey_zone_queue.append({
                    "pid": pid, "name": name, "path": path,
                    "score": t1_score, "frozen_at": time.time(),
                    "created": e["created"],
                })
        except Exception as ex:
            logger.error(f"[CLOUD ERROR]  {name}: {ex}")
            if e.get("exited_at"):
                return
            with grey_zone_lock:
                grey_zone_queue.append({
                    "pid": pid, "name": name, "path": path,
                    "score": t1_score, "frozen_at": time.time(),
                    "created": e["created"],
                })

    def stop(self):
        self._stop.set()


# ══════════════════════════════════════════════════════════════
# PHASE 6: GREY ZONE MONITOR (#6, #11)
# ══════════════════════════════════════════════════════════════

class GreyZoneMonitor:
    """
    Tracks grey-zone processes (running, flagged for Tier-2).
    On GREY_ZONE_TIMEOUT without a cloud verdict:
      - NETWORK_FAIL_POLICY = "OPEN"   -> leave running + warning
      - NETWORK_FAIL_POLICY = "CLOSED" -> kill() + critical log
    """

    def __init__(self):
        self._stop = threading.Event()

    def monitor(self):
        logger.info(
            f"Grey Zone Monitor started "
            f"(timeout={GREY_ZONE_TIMEOUT}s, policy={NETWORK_FAIL_POLICY})"
        )
        while not self._stop.wait(GREY_ZONE_CHECK_INTERVAL):
            self._check_timeouts()

    def _check_timeouts(self):
        now = time.time()
        timed_out = []
        with grey_zone_lock:
            remaining = []
            for entry in grey_zone_queue:
                if now - entry["frozen_at"] >= GREY_ZONE_TIMEOUT:
                    timed_out.append(entry)
                else:
                    remaining.append(entry)
            grey_zone_queue[:] = remaining
        for entry in timed_out:
            self._handle_timeout(entry)

    def _handle_timeout(self, entry: dict):
        pid, name = entry["pid"], entry["name"]
        score, exe_path = entry["score"], entry["path"]
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                raise psutil.NoSuchProcess(pid)
        except psutil.Error:
            logger.debug(f"Timeout: PID:{pid} {name} already exited")
            return

        if NETWORK_FAIL_POLICY == "CLOSED":
            _enforce_kill(proc, pid, name, exe_path,
                          f"[FAIL-CLOSED] {GREY_ZONE_TIMEOUT}s timeout score={score:.4f}")
        else:
            if NETWORK_FAIL_POLICY != "OPEN":
                logger.error(f"Unknown NETWORK_FAIL_POLICY='{NETWORK_FAIL_POLICY}', "
                             f"defaulting to OPEN")
            logger.warning(
                f"[FAIL-OPEN] PID:{pid} {name} left running after {GREY_ZONE_TIMEOUT}s "
                f"Cloud Timeout - Unverified -- score={score:.4f}  path={exe_path}"
            )

    def stop(self):
        self._stop.set()


# ══════════════════════════════════════════════════════════════
# PHASE 7: RESOURCE WATCHDOG (#13)
# ══════════════════════════════════════════════════════════════

class ResourceWatchdog:
    """
    Self-monitoring background thread that checks agent health.

    Every WATCHDOG_INTERVAL seconds:
      - RAM > RAM_THRESHOLD_MB   -> gc.collect() + warning
      - RAM > CRITICAL_RAM_MB    -> os._exit(75) for service restart
      - Otherwise                -> log health at DEBUG level

    Exit code 75 signals to a service manager / wrapper script
    that the agent should be restarted (not a crash, but cleanup).
    """

    def __init__(self):
        self._agent_proc = psutil.Process(os.getpid())
        self._running = True

    def monitor(self):
        """Main loop -- runs in daemon thread."""
        logger.info(
            f"Resource Watchdog started "
            f"(warn={RAM_THRESHOLD_MB}MB, critical={CRITICAL_RAM_MB}MB, "
            f"interval={WATCHDOG_INTERVAL}s)"
        )
        while self._running:
            time.sleep(WATCHDOG_INTERVAL)
            try:
                mem_info = self._agent_proc.memory_info()
                mem_mb = mem_info.rss / (1024 * 1024)
                cpu_pct = self._agent_proc.cpu_percent(interval=1)

                if mem_mb > CRITICAL_RAM_MB:
                    logger.critical(
                        f"[WATCHDOG] RAM={mem_mb:.0f}MB EXCEEDS CRITICAL "
                        f"({CRITICAL_RAM_MB}MB) -- initiating safe restart"
                    )
                    self._safe_restart()

                elif mem_mb > RAM_THRESHOLD_MB:
                    logger.warning(
                        f"[WATCHDOG] RAM={mem_mb:.0f}MB exceeds threshold "
                        f"({RAM_THRESHOLD_MB}MB) -- running cleanup"
                    )
                    self._cleanup()

                else:
                    logger.debug(
                        f"[WATCHDOG] Health OK -- RAM={mem_mb:.0f}MB, CPU={cpu_pct:.1f}%"
                    )

            except Exception as e:
                logger.error(f"[WATCHDOG] Monitor error: {e}")

    def _cleanup(self):
        """Attempt to free memory without restarting."""
        collected = gc.collect()
        logger.info(f"[WATCHDOG] GC collected {collected} objects")

    def _safe_restart(self):
        """Exit with code 75 -- service manager should restart us."""
        logger.critical("[WATCHDOG] Safe restart -- exiting with code 75")
        os._exit(75)

    def stop(self):
        self._running = False


# ══════════════════════════════════════════════════════════════
# PHASE 8: MAIN ENTRYPOINT
# ══════════════════════════════════════════════════════════════

BANNER = r"""
  _____ _____ _     _   _____  _    _     _____
 |_   _| ____| |   | | |_   _|/ \  | |   | ____|
   | | |  _| | |   | |   | | / _ \ | |   |  _|
   | | | |___| |___| |___| |/ ___ \| |___| |___
   |_| |_____|_____|_____|_/_/   \_\_____|_____|

   Telltale -- behavioral ransomware detection for Windows
   Endpoint agent v3.0  |  NETWORK_FAIL_POLICY: {policy}
"""


def is_admin() -> bool:
    """Check if the agent is running with administrator privileges. (#3)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    """
    Agent startup sequence:
      1. Print banner
      2. Admin check
      3. Populate self-PIDs
      4. Initialize ONNX, SQLite, SequenceExtractor
      5. Start daemon threads (grey zone monitor, resource watchdog)
      6. Start thread pool
      7. Start WMI listener (blocks main thread)
    """
    global inference_engine, sequence_extractor, whitelist_db, behavior_monitor, AGENT_MODE

    if "--mode" in sys.argv:
        i = sys.argv.index("--mode")
        AGENT_MODE = sys.argv[i + 1].strip().lower() if i + 1 < len(sys.argv) else AGENT_MODE
    if AGENT_MODE not in ("alert", "enforce"):
        logger.warning(f"Unknown mode '{AGENT_MODE}' -- using 'alert'")
        AGENT_MODE = "alert"

    print(BANNER.format(policy=NETWORK_FAIL_POLICY))
    logger.info(f"Mode: {AGENT_MODE.upper()}"
                + ("  -- threats are KILLED" if AGENT_MODE == "enforce"
                   else "  -- threats are logged only (use --mode enforce to kill)"))

    # ── #3: Admin privilege check ───────────────────────────
    if not is_admin():
        logger.critical(
            "AGENT REQUIRES ADMINISTRATOR PRIVILEGES.\n"
            "Win32_ProcessStartTrace needs admin/SYSTEM to receive events.\n"
            "Right-click -> 'Run as Administrator' or start from an elevated prompt."
        )
        sys.exit(1)

    logger.info("Admin privileges confirmed")

    # ── #1: Populate self-PIDs ──────────────────────────────
    agent_pid = os.getpid()
    SELF_PIDS.add(agent_pid)
    try:
        parent_pid = psutil.Process(agent_pid).ppid()
        SELF_PIDS.add(parent_pid)
    except Exception:
        pass
    logger.info(f"Self-PIDs registered: {SELF_PIDS}")

    # ── Initialize ONNX inference engine ────────────────────
    try:
        inference_engine = InferenceEngine(ONNX_MODEL_PATH)
    except FileNotFoundError as e:
        logger.critical(str(e))
        sys.exit(1)

    # ── Initialize BehavioralExtractor (#12) ────────────────
    sequence_extractor = make_extractor()

    # ── Initialize SQLite whitelist (#8 Layer 1B) ───────────
    whitelist_db = CustomWhitelist()

    # ── Start Grey Zone Monitor (#6, #11) ───────────────────
    gz_monitor = GreyZoneMonitor()
    gz_thread = threading.Thread(
        target=gz_monitor.monitor,
        name="GreyZone",
        daemon=True,
    )
    gz_thread.start()

    # ── Start Behavior Monitor (#16, #21) ───────────────────
    behavior_monitor = BehaviorMonitor()
    bm_thread = threading.Thread(
        target=behavior_monitor.monitor,
        name="BehaviorMon",
        daemon=True,
    )
    bm_thread.start()

    # ── Start Resource Watchdog (#13) ───────────────────────
    watchdog = ResourceWatchdog()
    wd_thread = threading.Thread(
        target=watchdog.monitor,
        name="Watchdog",
        daemon=True,
    )
    wd_thread.start()

    # ── Start Thread Pool (#9) ──────────────────────────────
    executor = ThreadPoolExecutor(
        max_workers=MAX_WORKERS,
        thread_name_prefix="Worker",
    )
    logger.info(f"Thread pool started (max_workers={MAX_WORKERS})")

    # ── Start WMI Listener ──────────────────────────────────
    logger.info("Starting WMI process monitor (Win32_ProcessStartTrace)...")
    logger.info("=" * 55)
    logger.info("  AGENT ACTIVE -- Monitoring all process creation")
    logger.info("  Press Ctrl+C to stop")
    logger.info("=" * 55)

    try:
        c = wmi.WMI()
        watcher = c.Win32_ProcessStartTrace.watch_for()

        while True:
            # (#25) finite timeout so Ctrl+C / shutdown is honoured
            try:
                event = watcher(timeout_ms=1000)
            except wmi.x_wmi_timed_out:
                continue
            pid = event.ProcessID
            name = event.ProcessName

            # Hand off to thread pool -- WMI listener free in <1ms (#9)
            executor.submit(handle_new_process, pid, name)

    except KeyboardInterrupt:
        logger.info("Ctrl+C received -- shutting down agent...")
    except Exception as e:
        logger.critical(f"WMI listener fatal error: {e}")
    finally:
        # ── Clean shutdown ──
        logger.info("Shutting down thread pool...")
        executor.shutdown(wait=False)
        gz_monitor.stop()
        behavior_monitor.stop()
        watchdog.stop()
        if hasattr(sequence_extractor, "stop"):
            sequence_extractor.stop()
        if whitelist_db:
            whitelist_db.close()
        logger.info("Agent stopped.")


if __name__ == "__main__":
    main()
