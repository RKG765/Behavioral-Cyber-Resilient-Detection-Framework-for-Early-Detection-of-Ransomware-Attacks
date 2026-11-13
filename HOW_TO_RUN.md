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

### Terminal 1: Launch the Tier-2 Service (`server.py`)
Hosts the Tier-2 residual MLP on port 8000 and scores grey-zone processes escalated by the agent. It has no authentication, so keep it on localhost.

```powershell
python -m uvicorn server:app --host 127.0.0.1 --port 8000
```
* **Health Check:** `http://127.0.0.1:8000/health`  
* **Output:** `{"status":"ok", "model":"tier2_behavioral.pt", "threshold":0.6546..., ...}` plus uptime and request / verdict counts

---

### Terminal 2: Launch Endpoint EDR Agent (`agent.py`)
The endpoint agent. It receives process-start events from WMI, runs the trust checks (signature, protected path, whitelist), scores unknown processes with the Tier 1 ONNX model using live Sysmon features from `edr_sensor`, and writes every verdict to `agent.log`. Run it from an **Administrator** prompt.

```powershell
python agent.py                  # alert mode (default): threats are logged, nothing is killed
python agent.py --mode enforce   # threats are killed
```
Without Sysmon and the `edr_sensor` extension it falls back to **simulated** features: it runs, but detects nothing and never kills.
*(Note: You can also start or stop `agent.py` with 1-click directly from the Streamlit Dashboard using the **"▶ Start Agent"** button!)*

---

### Terminal 3: Launch Streamlit Real-Time SOC Dashboard (`edr_soc_dashboard.py`)
The primary SOC command console. Uses Streamlit 1.56.0's native `@st.fragment(run_every="1s")` for **zero-refresh real-time monitoring**.

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
* **Same Wi-Fi / LAN:** the portal listens on `127.0.0.1` only. To show it on another device, start it with `$env:EDR_WEB_HOST = "0.0.0.0"` and open `http://<your-LAN-IP>:5050/how/` (trusted networks only: the portal has no authentication and can start or stop the agent).  
  - Complete storytelling presentation from basics to technical deep dive with Hinglish explainers.
  - Embedded high-res diagrams with interactive view toggling (Image vs. Live Mermaid).
  - Lightbox full-screen image zoom.
  - Interactive process lifecycle simulator.
  - **Evaluator Grilling Mode:** Expandable cross-questions and answers for defense.
* **WebSocket Real-Time Console (Local):** `http://127.0.0.1:5050/`  
* **WebSocket Real-Time Console (LAN, with `EDR_WEB_HOST=0.0.0.0`):** `http://<your-LAN-IP>:5050/`

---

## 3. How the Live Telemetry Pipeline Works (Data Flow Diagram)

```
[ Windows OS / Attack Simulator ]
                │
                ▼ (Process Spawn)
         [ agent.py ] ◄── Evaluates Tier 1 ONNX (~0.03 ms per call)
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
   - Point to the top gauge cards on the Streamlit dashboard; they show the live CPU load and the agent's resident memory (RSS).
     * In the live test the agent used about 85 MB RAM and ~3.7% of one core while idle; its watchdog warns above 150 MB.
     * Tier 1 is a ~21K-parameter MLP (ONNX: 11 KB graph + 84 KB weights); one inference takes about 0.03 ms on CPU.
3. **Demonstrate Fast-Path Filtering:**
   - Explain that trusted binaries never reach the model: critical OS processes in protected paths, binaries signed by an allow-listed publisher (`WinVerifyTrust`), binaries in protected Windows folders, and SHA-256 matches in `whitelist.db`. Results are cached by `(path, mtime, size)`.
   - Shells, script hosts and LOLBins (`powershell.exe`, `certutil.exe`, ...) are always monitored, even when signed.
4. **Trigger Attack Simulations (Live Zero-Refresh Demonstration):**
   - In the Streamlit dashboard under **🎯 Live Attack & Escalation Simulator**. The **Benign** and **Ransomware** buttons append prepared log lines to `agent.log`; no process is started, scored or killed. Only the **Grey-Zone** button calls a model.
     * **Click "🟢 Benign Software":** a row with a green `BENIGN` badge appears in the Triage Table (a prepared Tier-1 score of 0.03).
     * **Click "🟡 Grey-Zone Attack":** an amber `GREY ZONE` row appears, and one real malware sample (row 107 of `behavioral_dataset.npz`) is scored by the Tier 1 ONNX model (≈ 0.77, inside the grey zone) and POSTed to `server.py` (Terminal 1 logs the `POST /score`). Tier 2 scores it ≈ 0.87, above the 0.6546 threshold, so a `[CLOUD VERDICT] powershell_stealth.exe KILLED` row follows. If `server.py` is not running, a `CLOUD OFFLINE` row appears instead.
     * **Click "🔴 Ransomware Dropper":** a red `MALWARE KILLED` row appears immediately (a prepared Tier-1 score of 0.97 ≥ 0.90).
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

* **Dataset:** 1,470 balanced processes from LMD-2023 (735 benign, 735 malware), Splunk forwarder processes dropped.
* **Feature Representation:** 99 behavioral features from each process's first 50 Sysmon events (event counts, command-line flags, launch location, parent/child categories, network / file / registry / DNS activity, timing). No raw paths or usernames.
* **Validation:** 5 seeds × 5 folds, GroupKFold on `ProcessGuid`. Every sample has its own GUID, so this is effectively a plain 5-fold split, and each fold tunes its own threshold: treat these numbers as optimistic.
* **Tier 1 MLP (cross-validation):** 97.03% accuracy, AUC 0.9967, TPR 94.59%, FPR 0.49%. ~21K parameters, ~0.03 ms per inference.
* **Tier 2 Residual MLP (cross-validation):** 96.35% accuracy, AUC 0.9957, TPR 93.35%, FPR 0.60%, precision 99.36%. Threshold Θ = 0.6546.
* **Hold-out (294 unseen processes, the honest baseline):** two-tier pipeline TPR 92.1%, FPR 2.8%; 39% of processes landed in the Tier-1 grey zone.
