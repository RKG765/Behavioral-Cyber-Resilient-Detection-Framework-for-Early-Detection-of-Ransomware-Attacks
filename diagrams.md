# Enterprise Two-Tier EDR: Comprehensive Architectural Diagrams & Lifecycle Flows

This document contains the complete set of architectural diagrams, process lifecycle evaluation flows, dataset engineering pipelines, model schematics, and the engineering evolution story for the Enterprise Two-Tier EDR system.

---

## 1. Problem Statement: The Legacy EDR Trilemma

Traditional Endpoint Detection & Response (EDR) agents suffer from a fundamental engineering trade-off: **Compute vs. Context vs. Alert Fatigue**.

```mermaid
flowchart TD
    subgraph LegacyProblems["The Traditional EDR Dilemma"]
        A["All Telemetry Sent to Cloud"] -->|"Network Saturation & Bandwidth Costs"| B["Network Congestion & High Latency (300ms - 2s)"]
        B --> C["Delayed Threat Neutralization (Attacker executes before kill)"]
        
        D["Heavy Neural Networks on Endpoint"] -->|"High CPU & Memory Footprint"| E["Battery Drain & User Complaints (>15% CPU, >500MB RAM)"]
        E --> F["Endpoint Instability & Crashes"]
        
        G["Static Signatures & Threshold Rules"] -->|"High False Positive Rate"| H["SOC Alert Fatigue (95%+ False Alarms)"]
        H --> I["Missed True Zero-Day Threats"]
    end
    
    subgraph ProposedSolution["Our Proposed Two-Tier EDR Solution"]
        J["Tier 1: Ultra-Fast Edge Gatekeeper (<1.8ms, <150MB RSS)"]
        K["Tier 2: Deep Cloud Heavy Brain (ResNet + XAI Attribution)"]
        L["Asymmetric Grey-Zone Escalation (Only 5-10% sent to Cloud)"]
        
        J --> L
        L --> K
    end
    
    LegacyProblems -.->|"Solved By"| ProposedSolution
```

---

## 2. Full End-to-End Enterprise Two-Tier Architecture

The complete system workflow from kernel process spawn to automated remediation and SOC telemetry.

```mermaid
flowchart TB
    subgraph Endpoint["ENDPOINT WORKSTATION (Edge Tier 1)"]
        subgraph Ingestion["1. Process Interception"]
            WMI["Windows WMI / ETW Hook"] -->|"Process Create Event"| Worker["Worker Thread Pool"]
        end

        subgraph Tier0["2. Zero-Cost Fast-Path (L1 Whitelist)"]
            Worker -->|"Extract Binary Path & Hash"| L1A{"L1A: WinTrust Verification\n(OS Authenticode Signature)"}
            L1A -->|"Valid Microsoft / Vendor Cert"| AllowL1A["ALLOWED (Cached in LRU)\nZero CPU Inference Cost"]
            L1A -->|"Unsigned / Custom Exe"| L1B{"L1B: SQLite Whitelist Cache\n(Pre-approved Admin Hashes)"}
            L1B -->|"Hash Match"| AllowL1B["ALLOWED (Trusted DB)\nZero CPU Inference Cost"]
        end

        subgraph FeatureExtraction["3. 30-Second Behavioral Window"]
            L1B -->|"Unseen / Untrusted Binary"| BM["Behavior Monitor Engine\n(Watches for up to 30 seconds)"]
            BM -->|"Collect System Calls, File, Reg, Net"| Extractor["Behavioral Feature Extractor\n(Generates 99-dimensional vector)"]
        end

        subgraph Tier1Inference["4. Tier 1 Local Inference (<1.8ms)"]
            Extractor --> ONNX["Tier 1 ONNX Edge Model\n(Lightweight Behavioral MLP)"]
            ONNX -->|"Calculates Suspicion Score"| ThresholdT1{"Tier 1 Decision Engine\nScore Thresholding"}
        end

        subgraph EdgeDecisions["5. Edge Local Actions"]
            ThresholdT1 -->|"Score <= 0.10\n(Clear Benign)"| BenignAction["ALLOWED (Local Benign)\nLogged to agent.log"]
            ThresholdT1 -->|"Score >= 0.90\n(High Confidence Malware)"| KillAction["IMMEDIATE TERMINATION\nProcess Suspended & Killed\n< 2ms response time"]
            ThresholdT1 -->|"0.10 < Score < 0.90\n(Uncertain Grey Zone)"| Dispatch["Queue to Cloud Escalation Channel\n(Asynchronous HTTP POST)"]
        end
    end

    subgraph NetworkChannel["SECURE TRANSPORT"]
        Dispatch -->|"REST API (JSON Payload)\nPID, ProcessName, 99 Features"| CloudTunnel["FastAPI / Cloud Gateway\n(Port 8000 / HTTPS)"]
    end

    subgraph Cloud["ENTERPRISE CLOUD TIER 2 (Heavy Brain)"]
        subgraph Tier2Inference["6. Deep Behavioral Analysis"]
            CloudTunnel --> T2Model["Tier 2 Cloud ResNet Model\n(Residual Deep Network with BatchNorm1d)"]
            T2Model --> T2Eval{"Tier 2 Optimal Threshold\nScore > 0.6546"}
        end

        subgraph CloudDecisions["7. Cloud Verdict & XAI"]
            T2Eval -->|"Score <= 0.6546"| CloudAllow["Verdict: ALLOW\nLog as benign enterprise utility"]
            T2Eval -->|"Score > 0.6546"| CloudKill["Verdict: KILL\nConfidence: 90%+"]
            CloudKill --> XAI["Integrated Gradients (XAI)\nIdentify Top Suspicious Features"]
            CloudKill --> CloudRemediation["Dispatch Terminate Instruction\nBack to Endpoint Agent"]
        end
    end

    subgraph AnalystCockpit["SOC COMMAND CENTER"]
        CloudRemediation -.-> Webhook["Real-Time SOC Dashboard\n(FastAPI WebSockets / Streamlit)"]
        XAI -.-> Webhook
        EdgeDecisions -.-> Webhook
        Webhook --> Analyst["Security Analyst Cockpit\n(Quarantine, IP Blacklist, Host Isolation)"]
    end

    CloudRemediation -->|"Kill Signal"| Worker
```

---

## 3. Step-by-Step Criteria of Checking and Scoring a Process

How the EDR decides whether a process is allowed, monitored, escalated, or killed.

```mermaid
sequenceDiagram
    autonumber
    actor OS as Windows OS (Process Launch)
    participant EDR as agent.py (Endpoint)
    participant Cache as LRU / SQLite Whitelist
    participant T1 as Tier 1 ONNX (<1.8ms)
    participant Cloud as server.py (Tier 2 Cloud)
    participant Log as agent.log / SOC Dashboard

    OS->>EDR: New Process Spawn (e.g., brave.exe, powershell.exe)
    EDR->>Cache: Check LRU Cache & WinTrust Signature (L1A/L1B)
    alt Binary is Trusted & Validly Signed
        Cache-->>EDR: Match Found (Microsoft / Google / Whitelisted Hash)
        EDR->>Log: ALLOWED (Trusted / Zero Overhead)
    else Binary is Unknown or Unsigned
        Cache-->>EDR: Untrusted Binary
        EDR->>EDR: Register into BehaviorMonitor (30s Window)
        EDR->>EDR: Extract 99 Behavioral Features (File, Reg, Network, Process Tree)
        EDR->>T1: Run ONNX Inference (99 Features)
        T1-->>EDR: Return Tier-1 Suspicion Score (0.00 to 1.00)
        
        alt Score <= 0.10 (Benign)
            EDR->>Log: ALLOWED (Tier-1 Benign Score <= 0.10)
        else Score >= 0.90 (Clear Malware)
            EDR->>OS: Terminate Process immediately (taskkill / Win32 API)
            EDR->>Log: MALWARE TERMINATED (Score >= 0.90)
        else 0.10 < Score < 0.90 (Grey Zone)
            EDR->>Log: [GREY ZONE] Escalating to Cloud Server (Score: X)
            EDR->>Cloud: POST /score {process_name, tier1_score, features}
            Cloud->>Cloud: Run Tier-2 ResNet Model
            Cloud->>Cloud: Evaluate Optimal Operating Threshold (0.6546)
            alt Cloud Score > 0.6546
                Cloud-->>EDR: {"verdict": "KILL", "confidence": 0.88, "xai": {...}}
                EDR->>OS: Terminate Process (Cloud Directed)
                EDR->>Log: [CLOUD VERDICT] KILLED by Tier-2 Cloud ResNet
            else Cloud Score <= 0.6546
                Cloud-->>EDR: {"verdict": "ALLOW", "confidence": 0.32}
                EDR->>Log: [CLOUD VERDICT] ALLOWED by Tier-2 Cloud ResNet
            end
        end
    end
```

---

## 4. Dataset Pipeline & GroupKFold Leak-Free Splitting

```mermaid
flowchart TD
    subgraph RawData["Raw Telemetry & Sanitization"]
        R1["Raw Splunk Sysmon Logs\n(Benign vs Red-Team Malware)"] --> S1["Filter Splunk Ingestion Processes\n(splunk.exe, splunkd.exe removed)"]
        S1 --> S2["Sanitize Dynamic Artifacts\n(Usernames, GUID paths, Random PIDs)"]
    end

    subgraph FeatureEngineering["Behavioral Feature Engineering"]
        S2 --> F1["99 Engineered Behavioral Heuristics"]
        F1 --> F2["EventID Distribution Frequencies (1, 3, 7, 10, 11, 13)"]
        F1 --> F3["Process Tree & Path Anomalies (TempDir, Base64, AppData)"]
        F1 --> F4["File, Registry, and Network Socket Operations"]
        F1 --> F5["Window Fraction & Burst Execution Dynamics"]
        F2 & F3 & F4 & F5 --> M1["Balanced Dataset: 1,470 Process Traces\n(735 Benign : 735 Malware)"]
    end

    subgraph GroupSplitting["Rigorous Leak-Free Validation"]
        M1 --> G1{"GroupKFold Splitter\n(5 Folds, 5 Random Seeds)"}
        G1 -->|"Grouped Strictly by ProcessGuid"| TR["Training Folds (80%)"]
        G1 -->|"Grouped Strictly by ProcessGuid"| VA["Validation Folds (20%)"]
        
        note1["CRITICAL: Same process instance or child\nCANNOT appear in both Train and Test!\nEliminates 100% Data Leakage."]
        G1 -.-> note1
    end

    subgraph ModelTraining["Dual-Model Training Pipeline"]
        TR --> T1Train["Train Tier 1 Behavioral MLP\n(Focal Loss, Early Stopping)"]
        TR --> T2Train["Train Tier 2 Behavioral ResNet\n(BatchNorm1d, Residual Blocks)"]
    end
```

---

## 5. Tier 1 Edge Model Architecture (Sub-Millisecond ONNX)

```mermaid
graph LR
    Input["Input: 99 Behavioral Features\n[Batch, 99] Float32"] --> L1["Linear Layer\n(99 -> 128)"]
    L1 --> BN1["Batch Normalization\n(Feature Scaling)"]
    BN1 --> Act1["ReLU Activation"]
    Act1 --> Drop1["Dropout (0.30)\nRegularization"]
    
    Drop1 --> L2["Linear Layer\n(128 -> 64)"]
    L2 --> BN2["Batch Normalization"]
    BN2 --> Act2["ReLU Activation"]
    Act2 --> Drop2["Dropout (0.30)"]
    
    Drop2 --> OutL["Linear Head\n(64 -> 1 Logit)"]
    OutL --> Sigmoid["Sigmoid Function\n(Produces Probability [0, 1])"]
    
    Sigmoid --> Output["Edge Output Score\nInference Time: < 1.8ms\nModel Footprint: 10.8 KB ONNX"]
```

---

## 6. Tier 2 Cloud Model Architecture (Deep Heavy Brain ResNet)

```mermaid
graph TD
    Input["Input: 99 Behavioral Features\n[Batch, 99] Float32"] --> Proj["Initial Feature Projection\nLinear(99 -> 64)"]
    Proj --> BN0["BatchNorm1d\n(Feature Normalization)"]
    BN0 --> Act0["ReLU"]

    subgraph ResBlock1["Residual Block 1"]
        Act0 --> RB1_L1["Linear(64 -> 64)"]
        RB1_L1 --> RB1_BN1["BatchNorm1d"]
        RB1_BN1 --> RB1_Act1["ReLU"]
        RB1_Act1 --> RB1_L2["Linear(64 -> 64)"]
        RB1_L2 --> RB1_BN2["BatchNorm1d"]
        
        Act0 -.->|"Skip Connection (Identity)"| RB1_Add["Element-wise Sum (+)"]
        RB1_BN2 --> RB1_Add
        RB1_Add --> RB1_Out["ReLU Output"]
    end

    subgraph ResBlock2["Residual Block 2"]
        RB1_Out --> RB2_L1["Linear(64 -> 64)"]
        RB2_L1 --> RB2_BN1["BatchNorm1d"]
        RB2_BN1 --> RB2_Act1["ReLU"]
        RB2_Act1 --> RB2_L2["Linear(64 -> 64)"]
        RB2_L2 --> RB2_BN2["BatchNorm1d"]
        
        RB1_Out -.->|"Skip Connection (Identity)"| RB2_Add["Element-wise Sum (+)"]
        RB2_BN2 --> RB2_Add
        RB2_Add --> RB2_Out["ReLU Output"]
    end

    subgraph Head["Classification Head"]
        RB2_Out --> ClassL["Linear(64 -> 1)"]
        ClassL --> Sig["Sigmoid"]
        Sig --> FinalVerdict["Cloud Suspicion Score\nThreshold: 0.6546\nAccuracy: 97.03%\nAUC: 0.9967"]
    end
```

---

## 7. Evolution Journey: Problems Faced & How We Solved Them

```mermaid
timeline
    title EDR Engineering Evolution & Problem Resolution
    Phase 1 : Legacy Sequence CNN
            : EventID sequences only
            : Problem: Lack of context, High False Positives
    Phase 2 : Data Leakage Discovery
            : Random Train/Test Split leaked parent/child processes
            : Metric inflation (false 99.9% accuracy)
            : Solution: Strict 5-Seed GroupKFold by ProcessGuid
    Phase 3 : WinTrust OS API Lockups
            : Wintrust C-types calls hung threads on locked binaries
            : Solution: Worker Thread Pool with 1.5s timeout watchdog
    Phase 4 : Catastrophic Collapse on Fold 5
            : LayerNorm in Tier 2 failed under small batch seeds
            : Solution: Replaced LayerNorm with BatchNorm1d
            : Reduced Projection Dim to 64 for optimal convergence
    Phase 5 : Two-Tier Behavioral Production
            : 99 leak-free behavioral features
            : Tier 1 ONNX Edge (<1.8ms) + Tier 2 Cloud ResNet (99.26% Precision)
            : 99.51% Alert Fatigue Reduction
```
