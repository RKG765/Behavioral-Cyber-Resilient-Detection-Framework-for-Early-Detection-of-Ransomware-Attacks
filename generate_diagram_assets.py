"""
generate_diagram_assets.py
==========================
Generates 7 publication-grade, high-resolution architectural diagram PNGs
using Matplotlib in a dark cyber aesthetic (#0B111E / #111C2E).
These diagrams visually represent the Mermaid flows from diagrams.md and
are embedded directly into PowerPoint slides.

Outputs:
  how/assets/diag1_problem_trilemma.png
  how/assets/diag2_full_architecture.png
  how/assets/diag3_scoring_criteria.png
  how/assets/diag4_dataset_groupkfold.png
  how/assets/diag5_tier1_mlp.png
  how/assets/diag6_tier2_resnet.png
  how/assets/diag7_evolution_journey.png
"""

import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "how", "assets")
os.makedirs(OUT_DIR, exist_ok=True)

# Cyber Theme Palette
BG_COLOR     = "#0B111E"
CARD_BG      = "#111C2E"
BORDER_CYAN  = "#00E5FF"
BORDER_GREEN = "#00E676"
BORDER_AMBER = "#FFB300"
BORDER_RED   = "#FF1744"
TEXT_WHITE   = "#F1F5F9"
TEXT_MUTED   = "#94A3B8"
ARROW_COLOR  = "#64748B"

def draw_box(ax, x, y, w, h, title, subtitle="", border_color=BORDER_CYAN, fill_color=CARD_BG, title_color=TEXT_WHITE, fontsize=10):
    rect = patches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.03",
        linewidth=1.5,
        edgecolor=border_color,
        facecolor=fill_color,
        zorder=2
    )
    ax.add_patch(rect)
    
    if subtitle:
        ax.text(x + w/2, y + h*0.62, title, color=title_color, fontsize=fontsize, fontweight='bold', ha='center', va='center', zorder=3)
        ax.text(x + w/2, y + h*0.32, subtitle, color=TEXT_MUTED, fontsize=fontsize*0.82, ha='center', va='center', zorder=3)
    else:
        ax.text(x + w/2, y + h/2, title, color=title_color, fontsize=fontsize, fontweight='bold', ha='center', va='center', zorder=3)

def draw_arrow(ax, x1, y1, x2, y2, label="", color=ARROW_COLOR):
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle="->", color=color, lw=1.8, shrinkA=4, shrinkB=4),
        zorder=4
    )
    if label:
        mx, my = (x1 + x2)/2, (y1 + y2)/2
        ax.text(mx, my + 0.02, label, color=BORDER_CYAN, fontsize=8, fontweight='bold', ha='center', va='bottom', zorder=5)

# =============================================================================
# DIAGRAM 1: PROBLEM STATEMENT (THE LEGACY EDR TRILEMMA)
# =============================================================================
print("[*] Generating Diagram 1: Legacy EDR Trilemma...")
fig, ax = plt.subplots(figsize=(10, 5.5), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

# Legacy Nodes (Top 3)
draw_box(ax, 0.05, 0.65, 0.26, 0.25, "1. Cloud-Only EDR", "300ms - 2s Latency\nRansomware Encrypts First\nHigh Bandwidth Cost", BORDER_RED)
draw_box(ax, 0.37, 0.65, 0.26, 0.25, "2. Heavy Edge Model", "> 20% CPU Drain\n> 500 MB RAM Usage\nBattery Exhaustion", BORDER_AMBER)
draw_box(ax, 0.69, 0.65, 0.26, 0.25, "3. Heuristic Rules", "> 95% False Positives\nSOC Alert Fatigue\nMissed Zero-Days", BORDER_RED)

# Solution Box (Bottom)
draw_box(ax, 0.15, 0.12, 0.70, 0.32, "Proposed Solution: Asymmetric Two-Tier EDR Architecture",
         "Tier 1: Ultra-Fast Edge Gatekeeper (< 1.8ms CPU, < 150MB RSS, 10.8KB ONNX)\nTier 2: Cloud Heavy Brain (ResNet + BatchNorm1d + XAI Attribution)\nAsymmetric Protocol: 90%+ Resolved Locally; Only 5-10% Grey-Zone Escalated",
         BORDER_GREEN, fill_color="#0D223A", title_color=BORDER_GREEN, fontsize=11)

# Arrows
draw_arrow(ax, 0.18, 0.65, 0.35, 0.44, "Latency Solved")
draw_arrow(ax, 0.50, 0.65, 0.50, 0.44, "CPU Solved")
draw_arrow(ax, 0.82, 0.65, 0.65, 0.44, "Alert Fatigue Solved")

plt.tight_layout()
p1 = os.path.join(OUT_DIR, "diag1_problem_trilemma.png")
plt.savefig(p1, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

# =============================================================================
# DIAGRAM 2: FULL END-TO-END ARCHITECTURE
# =============================================================================
print("[*] Generating Diagram 2: Full End-to-End Architecture...")
fig, ax = plt.subplots(figsize=(12, 6.5), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1.2)
ax.set_ylim(0, 1)
ax.axis('off')

# Section Labels
ax.text(0.3, 0.95, "ENDPOINT WORKSTATION (Edge Tier 1)", color=BORDER_CYAN, fontsize=12, fontweight='bold', ha='center')
ax.text(0.95, 0.95, "ENTERPRISE CLOUD (Tier 2 Brain)", color=BORDER_AMBER, fontsize=12, fontweight='bold', ha='center')

# Endpoint Pipeline
draw_box(ax, 0.04, 0.76, 0.22, 0.14, "Kernel Intercept", "WMI / ETW Hook\nProcess Create Event", BORDER_CYAN)
draw_box(ax, 0.32, 0.76, 0.24, 0.14, "L1A WinTrust CA", "Authenticode Signature\n0.0ms LRU Cache", BORDER_GREEN)
draw_box(ax, 0.04, 0.54, 0.22, 0.14, "L1B SQLite Cache", "Pre-approved Hashes\n< 0.2ms Match", BORDER_GREEN)
draw_box(ax, 0.32, 0.54, 0.24, 0.14, "30s Behavioral Window", "Syscalls, Reg, Net, Files\n99 Feature Vector", BORDER_CYAN)
draw_box(ax, 0.18, 0.32, 0.26, 0.14, "Tier 1 ONNX Model", "MLP (99->128->64->1)\n< 1.8ms Edge Latency", BORDER_CYAN)

# Edge Gating Decisions
draw_box(ax, 0.02, 0.10, 0.17, 0.14, "Local Allow", "Score <= 0.10\nZero Network Egress", BORDER_GREEN)
draw_box(ax, 0.21, 0.10, 0.18, 0.14, "Local Terminate", "Score >= 0.90\nWin32 Kill (< 2ms)", BORDER_RED)
draw_box(ax, 0.41, 0.10, 0.18, 0.14, "Grey Zone Queue", "0.10 < Score < 0.90\nEscalate to Cloud", BORDER_AMBER)

# Cloud Pipeline
draw_box(ax, 0.72, 0.60, 0.22, 0.20, "FastAPI Gateway", "HTTP POST /score\nJSON Payload\n(PID, 99 Feats)", BORDER_AMBER)
draw_box(ax, 0.98, 0.60, 0.20, 0.20, "Tier 2 ResNet", "Deep Behavioral ResNet\nBatchNorm1d + Skips\nFocal Loss (gamma=2.0)", BORDER_CYAN)
draw_box(ax, 0.85, 0.28, 0.24, 0.20, "Optimal Threshold", "Theta = 0.6546\nFPR < 1.0%\n99.26% Precision", BORDER_AMBER)

draw_box(ax, 0.72, 0.05, 0.20, 0.15, "Cloud Allow", "Score <= 0.6546\nEnterprise Utility", BORDER_GREEN)
draw_box(ax, 0.96, 0.05, 0.22, 0.15, "Cloud Kill Order", "Score > 0.6546\n+ Integrated Gradients XAI", BORDER_RED)

# Connecting Arrows
draw_arrow(ax, 0.26, 0.83, 0.32, 0.83, "Signed?")
draw_arrow(ax, 0.44, 0.76, 0.15, 0.68, "Unsigned")
draw_arrow(ax, 0.26, 0.61, 0.32, 0.61, "Unknown")
draw_arrow(ax, 0.44, 0.54, 0.31, 0.46, "99 Feats")
draw_arrow(ax, 0.22, 0.32, 0.10, 0.24)
draw_arrow(ax, 0.31, 0.32, 0.30, 0.24)
draw_arrow(ax, 0.40, 0.32, 0.50, 0.24)

# Cloud Egress Arrow
draw_arrow(ax, 0.59, 0.17, 0.72, 0.65, "REST API (5-10%)")
draw_arrow(ax, 0.94, 0.70, 0.98, 0.70)
draw_arrow(ax, 1.08, 0.60, 0.97, 0.48)
draw_arrow(ax, 0.88, 0.28, 0.82, 0.20)
draw_arrow(ax, 1.02, 0.28, 1.07, 0.20)

plt.tight_layout()
p2 = os.path.join(OUT_DIR, "diag2_full_architecture.png")
plt.savefig(p2, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

# =============================================================================
# DIAGRAM 3: PROCESS SCORING CRITERIA LIFECYCLE
# =============================================================================
print("[*] Generating Diagram 3: Scoring Criteria Lifecycle...")
fig, ax = plt.subplots(figsize=(11, 5.8), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

# Step by Step flow
draw_box(ax, 0.05, 0.75, 0.24, 0.18, "Step 1: Ingestion & Fast-Path", "L1A: WinTrust Signature\nL1B: SQLite SHA-256\nMatch -> ALLOW (0.0ms)", BORDER_GREEN)
draw_box(ax, 0.38, 0.75, 0.24, 0.18, "Step 2: 30s Behavioral Window", "BehaviorMonitor Ring Buffers\nSyscalls, Reg, Net, File writes\nExtracts 99 Heuristic Features", BORDER_CYAN)
draw_box(ax, 0.71, 0.75, 0.24, 0.18, "Step 3: Tier 1 ONNX Scoring", "MLP Evaluates in 1.4ms\nProduces Suspicion Score\nS_T1 in [0.00, 1.00]", BORDER_CYAN)

draw_arrow(ax, 0.29, 0.84, 0.38, 0.84, "Untrusted")
draw_arrow(ax, 0.62, 0.84, 0.71, 0.84, "99 Vector")

# Branching Decisions
draw_box(ax, 0.05, 0.40, 0.26, 0.20, "Tier 1: S_T1 <= 0.10", "CLEAR BENIGN\nAction: Immediate Allow\nNetwork Cost: 0 KB", BORDER_GREEN)
draw_box(ax, 0.37, 0.40, 0.26, 0.20, "Tier 1: S_T1 >= 0.90", "CLEAR MALWARE\nAction: Instant Kill (<2ms)\nWin32 TerminateProcess", BORDER_RED)
draw_box(ax, 0.69, 0.40, 0.26, 0.20, "0.10 < S_T1 < 0.90", "GREY ZONE ESCALATION\nAction: POST to Cloud Tier 2\nSaves 90-95% Bandwidth", BORDER_AMBER)

draw_arrow(ax, 0.78, 0.75, 0.18, 0.60)
draw_arrow(ax, 0.83, 0.75, 0.50, 0.60)
draw_arrow(ax, 0.88, 0.75, 0.82, 0.60)

# Cloud Final Decisions
draw_box(ax, 0.20, 0.08, 0.28, 0.20, "Tier 2: S_T2 <= 0.6546", "CLOUD ALLOW\nCustomized Admin Utility\nLogged as Known Anomaly", BORDER_GREEN)
draw_box(ax, 0.55, 0.08, 0.35, 0.20, "Tier 2: S_T2 > 0.6546", "CLOUD KILL + XAI ATTRIBUTION\nAction: Immediate Agent Termination Order\nIntegrated Gradients Identifies Top Features", BORDER_RED)

draw_arrow(ax, 0.75, 0.40, 0.34, 0.28, "ResNet <= 0.6546")
draw_arrow(ax, 0.85, 0.40, 0.72, 0.28, "ResNet > 0.6546")

plt.tight_layout()
p3 = os.path.join(OUT_DIR, "diag3_scoring_criteria.png")
plt.savefig(p3, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

# =============================================================================
# DIAGRAM 4: DATASET & GROUPKFOLD PIPELINE
# =============================================================================
print("[*] Generating Diagram 4: Dataset Pipeline & GroupKFold...")
fig, ax = plt.subplots(figsize=(10.5, 5.5), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

draw_box(ax, 0.05, 0.68, 0.26, 0.22, "1. Raw Telemetry", "Splunk Sysmon Logs\nBenign Enterprise Activity\n+ Red-Team Malware Runs", BORDER_CYAN)
draw_box(ax, 0.37, 0.68, 0.26, 0.22, "2. Sanitization", "Drop splunk.exe / splunkd.exe\nStrip Usernames & Machine IDs\nEliminates Trivial Leakage", BORDER_AMBER)
draw_box(ax, 0.69, 0.68, 0.26, 0.22, "3. Balanced Dataset", "1,470 Total Process Traces\n735 Benign : 735 Malware\n99 Behavioral Features", BORDER_GREEN)

draw_arrow(ax, 0.31, 0.79, 0.37, 0.79)
draw_arrow(ax, 0.63, 0.79, 0.69, 0.79)

# GroupKFold Box
draw_box(ax, 0.15, 0.15, 0.70, 0.38, "CRITICAL: 5-Seed GroupKFold strictly by ProcessGuid",
         "The Flaw: Random split leaks parent & child processes across folds (False 99.9% Acc).\nThe Solution: All execution windows of a process family are strictly in Train OR Validation.\nIntersection(Groups_Train, Groups_Val) = EmptySet.\nEvaluated across 5 random seeds (42, 123, 456, 789, 2024) -> True Generalization Verified!",
         BORDER_GREEN, fill_color="#0D223A", title_color=BORDER_GREEN, fontsize=11)

draw_arrow(ax, 0.82, 0.68, 0.50, 0.53, "Grouped by ProcessGuid")

plt.tight_layout()
p4 = os.path.join(OUT_DIR, "diag4_dataset_groupkfold.png")
plt.savefig(p4, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

# =============================================================================
# DIAGRAM 5: TIER 1 MODEL ARCHITECTURE (MLP)
# =============================================================================
print("[*] Generating Diagram 5: Tier 1 MLP Architecture...")
fig, ax = plt.subplots(figsize=(11, 4.5), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

layers = [
    ("Input Layer", "[Batch, 99]\nFloat32 Features", BORDER_CYAN),
    ("Linear 1 + BN", "Linear(99->128)\nBatchNorm1d + ReLU", BORDER_CYAN),
    ("Dropout 1", "p = 0.30\nRegularization", BORDER_AMBER),
    ("Linear 2 + BN", "Linear(128->64)\nBatchNorm1d + ReLU", BORDER_CYAN),
    ("Dropout 2", "p = 0.30\nRegularization", BORDER_AMBER),
    ("Head + Sigmoid", "Linear(64->1)\nSigmoid Probability", BORDER_GREEN),
]

x_start = 0.03
width = 0.13
gap = 0.032

for i, (l_title, l_sub, l_col) in enumerate(layers):
    draw_box(ax, x_start + i*(width+gap), 0.35, width, 0.38, l_title, l_sub, l_col)
    if i < len(layers) - 1:
        draw_arrow(ax, x_start + i*(width+gap) + width, 0.54, x_start + (i+1)*(width+gap), 0.54)

# Bottom callout
ax.text(0.5, 0.15, "PROPERTIES: 10.8 KB ONNX Artifact | < 1.8ms Single-Core CPU Inference | < 150 MB Resident Memory",
        color=BORDER_GREEN, fontsize=10, fontweight='bold', ha='center')

plt.tight_layout()
p5 = os.path.join(OUT_DIR, "diag5_tier1_mlp.png")
plt.savefig(p5, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

# =============================================================================
# DIAGRAM 6: TIER 2 MODEL ARCHITECTURE (RESNET)
# =============================================================================
print("[*] Generating Diagram 6: Tier 2 ResNet Architecture...")
fig, ax = plt.subplots(figsize=(11, 5.5), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

draw_box(ax, 0.03, 0.55, 0.16, 0.28, "Input & Projection", "[Batch, 99]\n-> Linear(99->64)\nBatchNorm1d\n+ ReLU", BORDER_CYAN)
draw_box(ax, 0.24, 0.55, 0.23, 0.28, "Residual Block 1", "Linear(64->64) + BN1\n+ ReLU + Linear(64->64) + BN2\n(+) Identity Skip Connection", BORDER_AMBER)
draw_box(ax, 0.52, 0.55, 0.23, 0.28, "Residual Block 2", "Linear(64->64) + BN1\n+ ReLU + Linear(64->64) + BN2\n(+) Identity Skip Connection", BORDER_AMBER)
draw_box(ax, 0.80, 0.55, 0.17, 0.28, "Head & Output", "Linear(64->1)\nSigmoid Score\nTheta = 0.6546", BORDER_GREEN)

draw_arrow(ax, 0.19, 0.69, 0.24, 0.69)
draw_arrow(ax, 0.47, 0.69, 0.52, 0.69)
draw_arrow(ax, 0.75, 0.69, 0.80, 0.69)

# Bottom explanation of BatchNorm fix
draw_box(ax, 0.08, 0.10, 0.84, 0.32, "Why ResNet with BatchNorm1d for Tabular Behavioral Data?",
         "1. Captures Non-Linear Conjunctions: Temp execution AND Base64 AND DLL injection.\n2. Skip Connections: Eliminates vanishing gradients during deep backpropagation.\n3. BatchNorm1d Feature Normalization: Normalizes each feature across batch, preserving individual physical semantics.\n4. Performance: 97.03% Accuracy | 0.9967 AUC | 99.26% Precision | 99.51% False Alarm Drop",
         BORDER_GREEN, fill_color="#0D223A", title_color=BORDER_GREEN, fontsize=10)

plt.tight_layout()
p6 = os.path.join(OUT_DIR, "diag6_tier2_resnet.png")
plt.savefig(p6, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

# =============================================================================
# DIAGRAM 7: EVOLUTION JOURNEY & PROBLEMS SOLVED
# =============================================================================
print("[*] Generating Diagram 7: Evolution Journey...")
fig, ax = plt.subplots(figsize=(11, 5.5), facecolor=BG_COLOR)
ax.set_facecolor(BG_COLOR)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

phases = [
    ("Phase 1: EventID CNN", "Sequences only\nHigh false alarms\nEvent-insertion bypass", BORDER_RED),
    ("Phase 2: Leakage Discovery", "Random split leaked trees\nArtificial 99.9% accuracy\nGroupKFold adopted", BORDER_AMBER),
    ("Phase 3: WinTrust Deadlock", "WinVerifyTrust hung threads\nLocked files crashed agent\n1.5s Watchdog added", BORDER_AMBER),
    ("Phase 4: Fold 5 Collapse", "LayerNorm failed on tabular\nFold 5 AUC collapsed to 0.50\nFixed with BatchNorm1d", BORDER_RED),
    ("Phase 5: Production EDR", "Two-Tier Asymmetric EDR\n97.03% Acc | 0.9967 AUC\n99.51% Alert Fatigue Drop", BORDER_GREEN),
]

x_s = 0.02
w = 0.165
g = 0.03

for i, (title, desc, col) in enumerate(phases):
    draw_box(ax, x_s + i*(w+g), 0.35, w, 0.45, title, desc, col, fontsize=9)
    if i < len(phases) - 1:
        draw_arrow(ax, x_s + i*(w+g) + w, 0.57, x_s + (i+1)*(w+g), 0.57)

ax.text(0.5, 0.15, "EVOLUTION: From Fragile Heuristics & Training Collapses to a Resilient Two-Tier Production EDR",
        color=BORDER_CYAN, fontsize=10, fontweight='bold', ha='center')

plt.tight_layout()
p7 = os.path.join(OUT_DIR, "diag7_evolution_journey.png")
plt.savefig(p7, dpi=300, facecolor=BG_COLOR, bbox_inches='tight')
plt.close()

print("[SUCCESS] All 7 diagram assets successfully generated in how/assets/!")
