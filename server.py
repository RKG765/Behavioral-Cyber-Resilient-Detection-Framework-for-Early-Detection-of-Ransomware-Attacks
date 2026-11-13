"""
server.py
=========
Tier 2 EDR -- Cloud Backend FastAPI Server
Hosts the Tier-2 Behavioral ResNet model and provides a single scoring
endpoint that the Endpoint Agent (agent.py) calls when a process lands
in the Grey Zone.

Architecture:
    POST /score
    Body:  { "process_name": str,
             "tier1_score":  float,
             "features":     [float x 99] }
    Response: { "verdict":    "KILL" | "BENIGN",
                "confidence": float,
                "threshold":  float,
                "tier2_score": float,
                "tier1_score": float }

Model:    tier2_behavioral.pt  (Tier2BehavioralNet -- ResNet MLP 99->64->64->1)
Threshold: tier2_behavioral_threshold.json (data-driven, FPR < 1%)

Run:
    pip install -r requirements.txt
    uvicorn server:app --host 127.0.0.1 --port 8000
    (The API has no authentication -- keep it on localhost unless it sits
     behind a reverse proxy with TLS and auth.)

Demo flow:
    Terminal 1 (Cloud):    uvicorn server:app
    Terminal 2 (Endpoint): python agent.py
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import json
import time
import logging
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List

# ---------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("Tier2-Cloud")

# ---------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
MODEL_PT        = os.path.join(BASE_DIR, "tier2_behavioral.pt")
THRESHOLD_JSON  = os.path.join(BASE_DIR, "tier2_behavioral_threshold.json")

INPUT_DIM       = 99
PROJ_DIM        = 64
DROPOUT_RATE    = 0.4
DEVICE          = torch.device("cpu")       # Cloud inference on CPU is fine

KILL_VERDICT    = "KILL"
BENIGN_VERDICT  = "BENIGN"


# ---------------------------------------------------------------
# MODEL DEFINITION (must match train_tier2_behavioral.py exactly)
# ---------------------------------------------------------------

class ResidualBlock(nn.Module):
    """FC(d,d) -> BatchNorm1d -> ReLU -> Dropout -> FC(d,d) -> BatchNorm1d + skip."""
    def __init__(self, dim: int, dropout: float = 0.4):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
        )
        self.act = nn.ReLU()

    def forward(self, x):
        return self.act(x + self.block(x))


class Tier2BehavioralNet(nn.Module):
    """
    Residual MLP for 99-dim behavioral features.
    Projection (99->64) -> ResBlock -> ResBlock -> Dropout -> Linear(64->1).
    """
    def __init__(self, input_dim: int = INPUT_DIM, proj_dim: int = PROJ_DIM,
                 dropout: float = DROPOUT_RATE):
        super().__init__()
        self.proj = nn.Sequential(
            nn.Linear(input_dim, proj_dim),
            nn.BatchNorm1d(proj_dim),
            nn.ReLU(),
        )
        self.res1 = ResidualBlock(proj_dim, dropout=dropout)
        self.res2 = ResidualBlock(proj_dim, dropout=dropout)
        self.drop = nn.Dropout(dropout)
        self.head = nn.Linear(proj_dim, 1)

    def forward(self, x):
        x = self.proj(x)
        x = self.res1(x)
        x = self.res2(x)
        return self.head(self.drop(x))    # [B, 1] logit


# ---------------------------------------------------------------
# MODEL + THRESHOLD LOADER
# ---------------------------------------------------------------

def load_model_and_threshold():
    if not os.path.exists(MODEL_PT):
        raise FileNotFoundError(
            f"Tier-2 model not found: {MODEL_PT}\n"
            f"Run train_tier2_behavioral.py first."
        )
    model = Tier2BehavioralNet().to(DEVICE)
    state = torch.load(MODEL_PT, map_location=DEVICE)
    model.load_state_dict(state)
    model.eval()
    log.info(f"Loaded model: {MODEL_PT}")

    threshold = 0.65   # safe default
    if os.path.exists(THRESHOLD_JSON):
        with open(THRESHOLD_JSON, encoding="utf-8") as f:
            t = json.load(f)
        threshold = float(t.get("threshold", threshold))
        log.info(
            f"Loaded threshold: {threshold:.4f}  "
            f"(target FPR<{t.get('target_fpr',0.01)*100:.0f}%, "
            f"val TPR={t.get('val_tpr_mean',0)*100:.1f}%)"
        )
    else:
        log.warning(f"Threshold file not found: {THRESHOLD_JSON} -- using {threshold}")

    return model, threshold


# ---------------------------------------------------------------
# FASTAPI APP
# ---------------------------------------------------------------

app = FastAPI(
    title="EDR Tier-2 Cloud API",
    description=(
        "Behavioral ResNet classifier for Grey-Zone process escalation. "
        "Receives 99-feature vectors from the Endpoint Agent and returns "
        "KILL / BENIGN verdicts with confidence scores."
    ),
    version="1.0.0",
)

# Globals — loaded at startup
_model: Tier2BehavioralNet = None
_threshold: float = 0.65
_total_requests: int = 0
_kill_count: int    = 0
_start_time: float  = 0.0


@app.on_event("startup")
def startup():
    global _model, _threshold, _start_time
    _start_time = time.time()
    log.info("=" * 55)
    log.info("  TIER-2 CLOUD SERVER  --  Behavioral ResNet")
    log.info("  Waiting for Grey-Zone escalations from Agent...")
    log.info("=" * 55)
    _model, _threshold = load_model_and_threshold()


# ---------------------------------------------------------------
# REQUEST / RESPONSE SCHEMAS
# ---------------------------------------------------------------

class ScoreRequest(BaseModel):
    process_name: str = Field(..., description="Name of the grey-zone process")
    tier1_score:  float = Field(..., ge=0.0, le=1.0,
                                description="Tier-1 endpoint score that triggered escalation")
    features: List[float] = Field(..., min_items=INPUT_DIM, max_items=INPUT_DIM,
                                  description="99-dimensional behavioral feature vector")


class ScoreResponse(BaseModel):
    verdict:     str   = Field(..., description="KILL or BENIGN")
    confidence:  float = Field(..., description="Tier-2 probability score [0,1]")
    threshold:   float = Field(..., description="Decision threshold used")
    tier2_score: float = Field(..., description="Raw Tier-2 model output")
    tier1_score: float = Field(..., description="Original Tier-1 score from agent")
    process_name: str


# ---------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------

@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    global _total_requests, _kill_count

    _total_requests += 1
    t_start = time.perf_counter()

    # ── Prepare input tensor ──
    feat = np.array(req.features, dtype=np.float32).reshape(1, INPUT_DIM)
    x    = torch.tensor(feat, dtype=torch.float32).to(DEVICE)

    # ── Inference ──
    with torch.no_grad():
        logit = _model(x)
        prob  = float(torch.sigmoid(logit).squeeze())

    latency_ms = (time.perf_counter() - t_start) * 1000

    # ── Verdict ──
    verdict = KILL_VERDICT if prob >= _threshold else BENIGN_VERDICT
    if verdict == KILL_VERDICT:
        _kill_count += 1

    log.info(
        f"[{'KILL  ' if verdict == KILL_VERDICT else 'BENIGN'}]  "
        f"{req.process_name:<30}  "
        f"T1={req.tier1_score:.3f}  T2={prob:.3f}  "
        f"thr={_threshold:.3f}  {latency_ms:.1f}ms"
    )

    return ScoreResponse(
        verdict=verdict,
        confidence=prob,
        threshold=_threshold,
        tier2_score=prob,
        tier1_score=req.tier1_score,
        process_name=req.process_name,
    )


@app.get("/health")
def health():
    """Quick liveness check — also shows server stats."""
    uptime = time.time() - _start_time
    return {
        "status":           "ok",
        "model":            os.path.basename(MODEL_PT),
        "threshold":        _threshold,
        "uptime_seconds":   round(uptime, 1),
        "total_requests":   _total_requests,
        "kill_verdicts":    _kill_count,
        "benign_verdicts":  _total_requests - _kill_count,
    }


@app.get("/")
def root():
    return {
        "service": "EDR Tier-2 Cloud API",
        "endpoints": {
            "POST /score":  "Score a grey-zone process",
            "GET /health":  "Server liveness + stats",
        }
    }
