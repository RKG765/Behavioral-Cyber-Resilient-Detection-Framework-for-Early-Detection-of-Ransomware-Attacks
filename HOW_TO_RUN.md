# Telltale: Master Operational & Execution Guide (HOW TO RUN)

This document provides a comprehensive operational guide for the **Telltale** project. It details the purpose of every file in the repository, provides copy-pasteable execution commands, and outlines how to conduct a live evaluator demonstration.

---

## 1. Project Directory & File Reference Map

```
d:/project4/
├── agent.py                     # endpoint agent (alert mode by default)
├── test_agent.py                # agent test suite
├── server.py                    # Tier-2 FastAPI service
├── install_windows.ps1          # one-command setup (Sysmon + sensor + auto-start task)
├── edr_sensor/                  # Rust Sysmon feature sensor (+ live/ tests and Sysmon config)
├── train_tier1_behavioral.py    # Tier-1 behavioral MLP training (ONNX + PT)
├── train_tier2_behavioral.py    # Tier-2 behavioral ResNet training
├── build_behavioral_dataset.py  # LMD-2023 -> 99 behavioral features
├── tier1_behavioral.onnx, tier1_behavioral.pt, tier2_behavioral.pt
├── dataset/behavioral_dataset.npz
├── web_app.py + static/         # SOC command center on port 5050
├── edr_soc_dashboard.py         # Streamlit SOC dashboard on port 8501
├── how/                         # interactive walkthrough site (diagram PNGs in how/assets/)
├── site/                        # public landing & download page
├── generate_diagram_assets.py   # regenerates how/assets/*.png
├── diagrams.md                  # Mermaid diagram sources
└── architecture_and_feature_engineering.txt
```

---

## 2. Quickstart Execution Guide

To run the complete Telltale system with live real-time communication, use the following terminal setup:

### Terminal 1: Launch Cloud Heavy Brain (`server.py`)
Hosts the deep Behavioral ResNet model on port 8000. It receives escalated grey-zone processes from endpoints.

```powershell
python -m uvicorn server:app --host 127.0.0.1 --port 8000
```
* **Health Check:** `http://127.0.0.1:8000/health`  
* **Output:** `{"status":"ok", "model":"tier2_behavioral.pt", "threshold":0.6546}`

---

### Terminal 2: Launch Endpoint EDR Agent (`agent.py`)
The endpoint monitoring agent that hooks into Windows WMI/ETW kernel events, checks Level 1 whitelists, runs Tier 1 ONNX inference, and writes live telemetry to `agent.log`.

```powershell
python agent.py
```
*(Note: You can also start or stop `agent.py` with 1-click directly from the Streamlit Dashboard using the **"▶ Start Agent"** button!)*

---

### Terminal 3: Launch Streamlit Real-Time SOC Dashboard (`edr_soc_dashboard.py`)
The primary SOC command console matching your exact screenshot layout. Uses Streamlit 1.56.0's native `@st.fragment(run_every="1s")` for **zero-refresh real-time monitoring**.

```powershell
streamlit run edr_soc_dashboard.py --server.port 8501
```
* **Dashboard URL:** `http://127.0.0.1:8501`
* **Real-Time Data Ingestion:**
  - Automatically reads live log deltas from `agent.log` every second.
  - Queries live host CPU, host RAM, and `agent.py` process Resident Memory (RSS MB) via `psutil`.
  - Pings `server.py` on port 8000 to display live requests and kill counts.
  - Updates the gauges, KPI cards, and Triage Table without full-page reloads.

---

### Terminal 4 (Optional): Launch Interactive Presentation Website & Web App (`web_app.py`)
Serves both the interactive presentation website and the alternative WebSocket-based SOC console on port 5050.

```powershell
python web_app.py
```
* **Interactive Presentation Website (Local):** `http://127.0.0.1:5050/how/`  
* **Interactive Presentation Website (Same Wi-Fi / LAN Network):** `http://10.7.35.159:5050/how/`  
  - Complete storytelling presentation from basics to technical deep dive with Hinglish explainers.
  - Embedded high-res diagrams with interactive view toggling (Image vs. Live Mermaid).
  - Lightbox full-screen image zoom.
  - Interactive process lifecycle simulator.
  - **Evaluator Grilling Mode:** Expandable cross-questions and answers for defense.
* **WebSocket Real-Time Console (Local):** `http://127.0.0.1:5050/`  
* **WebSocket Real-Time Console (Same Wi-Fi / LAN Network):** `http://10.7.35.159:5050/`

---

## 3. How the Live Telemetry Pipeline Works (Data Flow Diagram)

```
[ Windows OS / Attack Simulator ]
                │
                ▼ (Process Spawn)
         [ agent.py ] ◄── Evaluates Tier 1 ONNX (<1.8ms)
                │
                ├─────────────────────────────────────┐
                │ (If Grey Zone 0.10 - 0.90)          │ (All Verdicts & Scores)
                ▼ (HTTP POST /score)                  ▼
          [ server.py ]                         [ agent.log ]
     (Tier 2 Cloud ResNet)                            │
                │                                     │
                └───────────────┬─────────────────────┘
                                │
                                ▼ (Continuous Polling via @st.fragment every 1s)
                   [ edr_soc_dashboard.py ] (Port 8501)
                                │
                                ├─► Live CPU & RAM Gauges (psutil)
                                ├─► EDR Resident Memory (RSS MB)
                                ├─► 5 Metric Cards (Events, PIDs, Allowed, Grey, Kills)
                                ├─► Cloud Backend Status (ONLINE | Requests: X | Kills: Y)
                                └─► Triage Events Table (Auto-updating without page refresh!)
```

---

## 4. How to Conduct a Live Evaluator / Professor Demonstration

Follow this exact sequence to demonstrate the system live:

1. **Open Terminals & Start Services:**
   - In Terminal 1: Run `python -m uvicorn server:app --host 127.0.0.1 --port 8000`.
   - In Terminal 2: Run `python agent.py` (or click **"▶ Start Agent"** in the dashboard).
   - In Terminal 3: Run `streamlit run edr_soc_dashboard.py --server.port 8501`.
   - Open your browser to `http://127.0.0.1:8501`.
2. **Demonstrate Hardware Telemetry (The Edge Value Proposition):**
   - Point to the top gauge cards on the Streamlit dashboard:
     * CPU Load is typically 0.0% idle drain.
     * EDR Resident Memory (RSS) sits around ~138 MB, visibly passing the `< 150 MB` budget badge.
     * Point out that Tier 1's ONNX model footprint is only **10.8 KB** and local inference latency is **< 1.8 ms**.
3. **Demonstrate Fast-Path Ingestion & Zero-Cost Filtering:**
   - Explain how Level 1A (WinTrust Authenticode) verifies signed binaries (Chrome, Explorer) with **0.0ms ML overhead**, and Level 1B checks `whitelist.db` in **< 0.2ms**.
4. **Trigger Attack Simulations (Live Zero-Refresh Demonstration):**
   - In the Streamlit dashboard under **🎯 Live Attack & Escalation Simulator**:
     * **Click "🟢 Benign Software":** Notice a new row appears in the Triage Table with a green `BENIGN` badge. The process was scored <= 0.10 and allowed locally with zero network egress.
     * **Click "🟡 Grey-Zone Attack":** Notice the row appears with an amber `GREY ZONE` badge. In Terminal 1, you will see a live `POST /score` request logged by `server.py`. The Cloud ResNet evaluates the 99 features, applies threshold $\Theta = 0.6546$, returns a `KILL` verdict, and the dashboard updates with a `[CLOUD VERDICT] powershell_stealth.exe KILLED` entry.
     * **Click "🔴 Ransomware Dropper":** A red `MALWARE KILLED` badge appears immediately. Tier 1 scored $\ge 0.90$ and terminated the process in under 2ms without waiting for cloud round-trip.
5. **Show the Interactive Presentation & Evaluator Grilling Mode:**
   - In Terminal 4: Run `python web_app.py` and open `http://127.0.0.1:5050/how/` in a new tab.
   - Walk through the interactive chapters, toggle between diagram views, open the Lightbox zoom, and demonstrate the **Evaluator Grilling Mode** accordion to answer tough questions.

---

## 5. Architectural Ports & Endpoints Summary

| Service | Port | Protocol | Primary Endpoints | Description |
|---|---|---|---|---|
| **Cloud Tier 2** | `8000` | HTTP / REST | `/health`, `/score` | Deep Behavioral ResNet Cloud Brain |
| **Streamlit SOC** | `8501` | HTTP / WS | `/` | Modular real-time dashboard with `@st.fragment` |
| **FastAPI Web App** | `5050` | HTTP / WS | `/`, `/how/`, `/ws`, `/api/simulate` | Presentation website & WebSockets telemetry |

---

## 6. Key Scientific & Engineering Benchmarks Reference

* **Dataset:** 1,470 balanced process traces (735 benign enterprise sysmon traces, 735 red-team malware executions).
* **Feature Representation:** 99 engineered continuous behavioral features (EventID ratios, execution velocity, Base64 detection, volatile path heuristics, tree depth).
* **Validation Rigor:** Strict 5-Seed GroupKFold cross-validation grouped strictly by `ProcessGuid` (Zero data leakage).
* **Tier 1 ONNX Edge Performance:** 95.84% Mean Accuracy, 0.9892 AUC, < 1.8ms Single-Core CPU Latency, 10.8 KB Footprint, 138.4 MB Resident Memory.
* **Tier 2 Cloud ResNet Performance:** 97.03% Mean Accuracy, 0.9967 AUC, 99.26% Precision at FPR < 1.0% ($\Theta = 0.6546$).
* **Enterprise SOC Impact:** 99.51% false positive alert suppression; 95% reduction in cloud telemetry transmission costs.
