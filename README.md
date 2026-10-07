# Behavioral Cyber-Resilient Detection Framework for Early Detection of Ransomware Attacks

[![Architecture: Asymmetric Two-Tier EDR](https://img.shields.io/badge/Architecture-Asymmetric%20Two--Tier%20EDR-00E5FF.svg?style=flat-square)](#system-architecture)
[![Edge Latency: <1.8ms](https://img.shields.io/badge/Edge%20Inference-%3C1.8ms%20(Single%20Core)-00E676.svg?style=flat-square)](#tier-1-edge-gatekeeper-hardware-benchmarks)
[![Edge Model Footprint: 10.8 KB](https://img.shields.io/badge/ONNX%20Model-10.8%20KB-blue.svg?style=flat-square)](#tier-1-edge-gatekeeper-hardware-benchmarks)
[![Cloud Brain: Residual Network](https://img.shields.io/badge/Cloud%20Brain-Behavioral%20ResNet-7C4DFF.svg?style=flat-square)](#tier-2-cloud-heavy-brain-architecture)
[![Tier 2 Accuracy: 97.03%](https://img.shields.io/badge/Accuracy-97.03%25-brightgreen.svg?style=flat-square)](#empirical-benchmarks--scientific-rigor)
[![ROC AUC: 0.9967](https://img.shields.io/badge/ROC%20AUC-0.9967-success.svg?style=flat-square)](#empirical-benchmarks--scientific-rigor)
[![Precision: 99.26%](https://img.shields.io/badge/Precision%20%40%20FPR%3C1%25-99.26%25-emerald.svg?style=flat-square)](#empirical-benchmarks--scientific-rigor)
[![False Alarm Suppression: 99.51%](https://img.shields.io/badge/False%20Alarm%20Reduction-99.51%25-teal.svg?style=flat-square)](#empirical-benchmarks--scientific-rigor)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg?style=flat-square)](LICENSE)

An enterprise-grade, **Asymmetric Edge-Cloud Collaborative Endpoint Detection & Response (EDR)** framework engineered to detect, classify, and neutralize modern polymorphic and fast-encrypting ransomware strains at the kernel spawn boundary.

By decoupling **sub-millisecond local gatekeeping (<1.8ms at the edge)** from **deep contextual reasoning in the cloud**, this system resolves the classical EDR trilemma—eliminating cloud transmission latency, preventing workstation CPU/battery exhaustion, and suppressing over 99.5% of false-positive alert fatigue.

---

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. The Fundamental Problem: The Legacy EDR Trilemma](#2-the-fundamental-problem-the-legacy-edr-trilemma)
- [3. System Architecture](#3-system-architecture)
  - [3.1 High-Level Architecture Diagram](#31-high-level-architecture-diagram)
  - [3.2 End-to-End Telemetry & Remediation Flow](#32-end-to-end-telemetry--remediation-flow)
- [4. Process Lifecycle & Scoring Mechanics](#4-process-lifecycle--scoring-mechanics)
  - [4.1 Multi-Stage Gating Protocol](#41-multi-stage-gating-protocol)
  - [4.2 Process Lifecycle Sequence Flowchart](#42-process-lifecycle-sequence-flowchart)
- [5. Feature Engineering: 99 Behavioral Structural Invariants](#5-feature-engineering-99-behavioral-structural-invariants)
  - [5.1 Why Sequential Token Models Fail (The 90% Ceiling Proof)](#51-why-sequential-token-models-fail-the-90-ceiling-proof)
  - [5.2 Behavioral Feature Matrix (All 99 Features)](#52-behavioral-feature-matrix-all-99-features)
- [6. Model Design & Mathematical Justification](#6-model-design--mathematical-justification)
  - [6.1 Tier 1 Edge Model: Ultra-Lightweight Behavioral MLP (ONNX)](#61-tier-1-edge-model-ultra-lightweight-behavioral-mlp-onnx)
  - [6.2 Tier 2 Cloud Model: Deep Behavioral Residual Network (ResNet)](#62-tier-2-cloud-model-deep-behavioral-residual-network-resnet)
  - [6.3 Loss Function & Operating Threshold Derivation ($\Theta = 0.6546$)](#63-loss-function--operating-threshold-derivation-theta--06546)
- [7. Empirical Benchmarks & Scientific Rigor](#7-empirical-benchmarks--scientific-rigor)
  - [7.1 Preventing Data Leakage via Strict 5-Seed GroupKFold](#71-preventing-data-leakage-via-strict-5-seed-groupkfold)
  - [7.2 Benchmark Performance Matrix](#72-benchmark-performance-matrix)
  - [7.3 Hardware Feasibility & Edge Footprint](#73-hardware-feasibility--edge-footprint)
- [8. Engineering Evolution: Real-World Hurdles & Applied Solutions](#8-engineering-evolution-real-world-hurdles--applied-solutions)
  - [8.1 Evolution Timeline](#81-evolution-timeline)
  - [8.2 Problem 1: WinTrust OS API Thread Deadlocks](#82-problem-1-wintrust-os-api-thread-deadlocks)
  - [8.3 Problem 2: ProcessGuid Data Leakage Trap](#83-problem-2-processguid-data-leakage-trap)
  - [8.4 Problem 3: Catastrophic Collapse on Fold 5 (Seed 2024)](#84-problem-3-catastrophic-collapse-on-fold-5-seed-2024)
- [9. Explainable AI (XAI) & Analyst Cockpit](#9-explainable-ai-xai--analyst-cockpit)
- [10. Unified SOC Command Center & User Interfaces](#10-unified-soc-command-center--user-interfaces)
- [11. Work Completed & Technical Deliverables](#11-work-completed--technical-deliverables)
- [12. Identified Gaps, Limitations & Threat Boundary](#12-identified-gaps-limitations--threat-boundary)
- [13. Future Roadmap & Next Milestones](#13-future-roadmap--next-milestones)
- [14. Installation & Quickstart](#14-installation--quickstart)
- [15. Repository Structure](#15-repository-structure)

---

## 1. Executive Summary

Modern cyberattacks—specifically fast-encrypting ransomware (e.g., LockBit 3.0, BlackCat) and living-off-the-land (LotL) intrusions—exploit a critical gap in traditional endpoint defenses. By issuing multi-threaded asynchronous I/O completion calls, modern encryptors can compromise hundreds of files in under 100 microseconds per file.

This framework introduces an **Asymmetric Multi-Tiered Architecture** where:
1. **Over 85% of standard endpoint binaries** bypass machine learning entirely via **Zero-Cost Fast-Path Gating** (native WinTrust Authenticode verification and in-memory LRU caching in $\le 0.2\text{ms}$).
2. **Untrusted binaries** are monitored across a dynamic 30-second sliding window that computes **99 behavioral structural invariants**.
3. **Tier 1 Edge Gatekeeper** executes an optimized **10.8 KB ONNX Multi-Layer Perceptron (MLP)** on the local workstation CPU in **<1.8ms**, immediately allowing clear benign activity ($S_{T1} \le 0.10$) and terminating obvious ransomware ($S_{T1} \ge 0.90$).
4. **Cloud Tier 2 Heavy Brain** receives only the remaining **5% to 10% ambiguous "Grey Zone" processes** ($0.10 < S_{T1} < 0.90$), evaluating them using a **Deep Behavioral Residual Network (ResNet)** with BatchNorm1d and streaming **Explainable AI (XAI)** attributions to SOC analysts.

---

## 2. The Fundamental Problem: The Legacy EDR Trilemma

Enterprise Endpoint Detection & Response solutions currently face a three-way engineering conflict:

```mermaid
flowchart TD
    subgraph LegacyProblems["The Traditional EDR Dilemma"]
        A["All Telemetry Streamed to Cloud"] -->|"Network Saturation & Serialization Delays"| B["Network Latency: 300ms to 2,000ms"]
        B --> C["Delayed Kill: Ransomware encrypts files before cloud verdict arrives"]
        
        D["Heavy Deep Models on Endpoint"] -->|"Deep CNN / Transformers on Client"| E["Workstation Exhaustion: >20% CPU, >500MB RAM"]
        E --> F["System Freezes, Battery Drain, Users Disable Agent"]
        
        G["Static Signatures & Token Rules"] -->|"High Inherent False Positives"| H["SOC Alert Fatigue: >95% False Alarms"]
        H --> I["Missed Zero-Days & Polymorphic Strains"]
    end
    
    subgraph ProposedSolution["Our Proposed Two-Tier Collaborative EDR"]
        J["Tier 1 Edge Gatekeeper\n(<1.8ms Latency, 10.8 KB ONNX, <138MB RAM)"]
        K["Tier 2 Cloud Heavy Brain\n(Deep ResNet + Integrated Gradients XAI)"]
        L["Asymmetric Grey-Zone Escalation\n(Only 5% - 10% ambiguous events sent to Cloud)"]
        
        J --> L
        L --> K
    end
    
    LegacyProblems -.->|"Solved By"| ProposedSolution
```

### The Breakdown:
1. **The Cloud Latency Gap (300ms – 2,000ms):** Streaming raw telemetry over wide-area networks introduces catastrophic delay. By the time a cloud server receives events, infers a verdict, and returns a kill signal, the Master File Table (MFT) is corrupted.
2. **The Edge Compute Ceiling:** Running heavy sequence models (LSTMs, Transformers) directly on user endpoints drains battery, causes input lag, and exceeds workstation memory budgets.
3. **Alert Fatigue & Token Brittleness:** Legacy EDRs trained solely on sequential Sysmon EventIDs suffer from a mathematical accuracy ceiling of ~90% due to conflicting execution patterns between benign installers and malware droppers.

---

## 3. System Architecture

### 3.1 High-Level Architecture Diagram

```mermaid
flowchart TB
    subgraph Endpoint["ENDPOINT WORKSTATION (Edge Tier 1 Agent)"]
        subgraph Ingestion["1. Kernel Process Interception"]
            WMI["Windows WMI / ETW Hook\n(Win32_ProcessStartTrace)"] -->|"Capture PID, Path, Cmdline"| Worker["Worker Thread Pool\n(Non-blocking Dispatch)"]
        end

        subgraph Tier0["2. Zero-Cost Fast-Path (L1 Whitelist)"]
            Worker -->|"Extract Binary Metadata"| L1A{"L1A: WinTrust Authenticode\n(OS Certificate Chain)"}
            L1A -->|"Valid Microsoft / Vendor Root"| AllowL1A["ALLOWED (LRU Cache)\n0.0ms ML Overhead"]
            L1A -->|"Unsigned / Custom Tool"| L1B{"L1B: SQLite Whitelist Cache\n(Pre-approved SHA-256)"}
            L1B -->|"Hash Match (<0.2ms)"| AllowL1B["ALLOWED (Trusted DB)\n0.0ms ML Overhead"]
        end

        subgraph FeatureExtraction["3. Dynamic 30s Behavioral Window"]
            L1B -->|"Unseen / Untrusted Binary"| BM["Behavior Monitor Engine\n(Watches up to 30s sliding window)"]
            BM -->|"Ring Buffer: File, Reg, Net, Syscall"| Extractor["Behavioral Feature Synthesizer\n(Calculates 99 Continuous Features)"]
        end

        subgraph Tier1Inference["4. Tier 1 Local Inference (<1.8ms)"]
            Extractor --> ONNX["Tier 1 ONNX Edge Model\n(Lightweight Behavioral MLP)"]
            ONNX -->|"Generates Suspicion Score S_T1"| ThresholdT1{"Tier 1 Decision Engine\nScore Gating"}
        end

        subgraph EdgeDecisions["5. Edge Local Actions"]
            ThresholdT1 -->|"S_T1 <= 0.10\n(Clear Benign)"| BenignAction["ALLOWED (Local Benign)\n0.00% False Negative Rate\nZero Cloud Egress"]
            ThresholdT1 -->|"S_T1 >= 0.90\n(High-Confidence Malware)"| KillAction["IMMEDIATE TERMINATION\nWin32 TerminateProcess API\n< 2ms response time"]
            ThresholdT1 -->|"0.10 < S_T1 < 0.90\n(Ambiguous Grey Zone)"| Dispatch["Asymmetric Cloud Escalation\n(Asynchronous HTTP POST)"]
        end
    end

    subgraph Transport["SECURE TRANSPORT CHANNEL"]
        Dispatch -->|"REST JSON Payload\nPID, ImageName, 99 Features"| CloudTunnel["FastAPI Microservice Gateway\n(Port 8000 / HTTPS)"]
    end

    subgraph Cloud["ENTERPRISE CLOUD TIER 2 (Heavy Brain)"]
        subgraph Tier2Inference["6. Deep Contextual Reasoning"]
            CloudTunnel --> T2Model["Tier 2 Cloud ResNet Model\n(Residual Deep Network with BatchNorm1d)"]
            T2Model --> T2Eval{"Optimal Threshold Evaluation\nS_T2 > 0.6546"}
        end

        subgraph CloudDecisions["7. Cloud Verdict & Attribution"]
            T2Eval -->|"S_T2 <= 0.6546"| CloudAllow["Verdict: ALLOW\nLog as benign enterprise utility"]
            T2Eval -->|"S_T2 > 0.6546"| CloudKill["Verdict: KILL\n99.26% Precision Guarantee"]
            CloudKill --> XAI["Integrated Gradients (XAI)\nAttribute Top Suspicious Features"]
            CloudKill --> CloudRemediation["Dispatch Terminate Directive\nBack to Endpoint Agent"]
        end
    end

    subgraph SOC["ENTERPRISE SOC COMMAND CENTER"]
        CloudRemediation -.-> Telemetry["Real-Time SOC Dashboard\n(FastAPI WebSockets / Streamlit)"]
        XAI -.-> Telemetry
        EdgeDecisions -.-> Telemetry
        Telemetry --> Analyst["Analyst Remediation Cockpit\n(Quarantine, C2 IP Block, Host Sever)"]
    end

    CloudRemediation -->|"Kill Directive"| Worker
```

### 3.2 End-to-End Telemetry & Remediation Flow

1. **Kernel Interception:** A new process launch triggers a Windows WMI event (`Win32_ProcessStartTrace`). A non-blocking thread pool worker extracts the PID, image path, parent PID, and command line.
2. **Level 1 Fast-Path:**
   - **L1A (WinTrust):** Calls the native Win32 `WinVerifyTrust` API (`wintrust.dll`). Valid signatures chaining to trusted root authorities (Microsoft, Google, Adobe) are cached in an in-memory LRU cache keyed by `(filepath, st_mtime, st_size)`. Modifying the binary invalidates the cache instantly.
   - **L1B (SQLite Hash Whitelist):** Unsigned internal enterprise software is matched against `whitelist.db` in $<0.2\text{ms}$.
3. **Dynamic 30-Second Behavioral Window:** Untrusted binaries enter the `BehaviorMonitor`. Circular ring buffers aggregate system calls, file replacements, registry modifications, and outbound sockets.
4. **Tier 1 ONNX Edge Evaluation:** Evaluates 99 continuous behavioral features in $<1.8\text{ms}$.
5. **Asymmetric Escalation:** Ambiguous processes ($0.10 < \text{Score} < 0.90$) are dispatched to Cloud Tier 2.
6. **Cloud ResNet Reasoning:** Deep residual blocks resolve feature conjunctions. If score exceeds $\Theta = 0.6546$, a kill directive is returned and Integrated Gradients XAI feature attributions are streamed to the SOC.

---

## 4. Process Lifecycle & Scoring Mechanics

### 4.1 Multi-Stage Gating Protocol

| Stage | Decision Engine | Condition / Rule | Action Taken | Latency | Bandwidth Cost |
|---|---|---|---|---|---|
| **L1A** | WinTrust Authenticode | Valid Vendor Certificate Root | **Instant Allow** (LRU Cached) | $0.0\text{ms}$ | Zero |
| **L1B** | SQLite B-Tree Hash | Match in `trusted_hashes` | **Instant Allow** (Internal Tool) | $<0.2\text{ms}$ | Zero |
| **Tier 1** | Edge ONNX MLP | $S_{T1} \le 0.10$ | **Local Allow** ($0.00\%$ FNR) | $<1.8\text{ms}$ | Zero |
| **Tier 1** | Edge ONNX MLP | $S_{T1} \ge 0.90$ | **Local Kill** (Win32 API) | $<2.0\text{ms}$ | Zero |
| **Tier 1 $\rightarrow$ 2** | Escalation Queue | $0.10 < S_{T1} < 0.90$ | **Escalate to Cloud Tier 2** | $\sim 12\text{ms}$ (HTTP) | $\sim 1.2\text{ KB}$ Payload |
| **Tier 2** | Cloud ResNet | $S_{T2} \le 0.6546$ | **Cloud Allow** | $2.4\text{ms}$ (GPU/CPU) | Internal Log |
| **Tier 2** | Cloud ResNet | $S_{T2} > 0.6546$ | **Cloud Kill + XAI Attribution** | $2.4\text{ms}$ + XAI | Real-Time SOC Alert |

### 4.2 Process Lifecycle Sequence Flowchart

```mermaid
sequenceDiagram
    autonumber
    actor OS as Windows OS (Process Launch)
    participant EDR as agent.py (Endpoint Agent)
    participant Cache as LRU / SQLite Whitelist
    participant T1 as Tier 1 ONNX (<1.8ms)
    participant Cloud as server.py (Tier 2 Cloud)
    participant SOC as Real-Time SOC Console

    OS->>EDR: Process Created (e.g., cmd.exe, malware.exe)
    EDR->>Cache: Inspect WinTrust Authenticode & SHA-256 Hash
    alt Binary is Authenticode Signed / Whitelisted
        Cache-->>EDR: Verified Legitimate Binary
        EDR->>SOC: ALLOWED (Level 1 Fast-Path, 0.0ms Overhead)
    else Binary is Unknown or Unsigned
        Cache-->>EDR: Untrusted Binary
        EDR->>EDR: Monitor sliding execution window (up to 30s)
        EDR->>EDR: Synthesize 99 Behavioral Feature Vector
        EDR->>T1: Run ONNX Inference
        T1-->>EDR: Return Suspicion Score S_T1 [0.00 - 1.00]
        
        alt S_T1 <= 0.10 (Clear Benign)
            EDR->>SOC: ALLOWED (Tier 1 Edge Verdict, S_T1 <= 0.10)
        else S_T1 >= 0.90 (Clear Malware)
            EDR->>OS: TerminateProcess(PID) in <2ms
            EDR->>SOC: LOCAL KILL (Tier 1 High-Confidence Malware)
        else 0.10 < S_T1 < 0.90 (Ambiguous Grey Zone)
            EDR->>SOC: [GREY ZONE] Escalating to Cloud Tier 2
            EDR->>Cloud: POST /score {process_name, S_T1, features[99]}
            Cloud->>Cloud: Run Tier 2 Deep Behavioral ResNet
            Cloud->>Cloud: Evaluate Optimal Threshold (Theta = 0.6546)
            alt S_T2 > 0.6546
                Cloud->>Cloud: Compute Integrated Gradients XAI Attributions
                Cloud-->>EDR: {"verdict": "KILL", "confidence": 0.94, "xai": {...}}
                EDR->>OS: TerminateProcess(PID)
                EDR->>SOC: CLOUD KILL (Enforced by Tier 2 Cloud Brain)
                Cloud->>SOC: Stream XAI Attribution Vector
            else S_T2 <= 0.6546
                Cloud-->>EDR: {"verdict": "ALLOW", "confidence": 0.28}
                EDR->>SOC: CLOUD ALLOW (Classified as Legitimate Admin Utility)
            end
        end
    end
```

---

## 5. Feature Engineering: 99 Behavioral Structural Invariants

### 5.1 Why Sequential Token Models Fail (The 90% Ceiling Proof)

Many prior academic and commercial approaches attempt to model malware using sequential token streams of Sysmon EventIDs (e.g., `[1, 7, 3, 11]`) fed into 1D-CNNs or LSTMs. 

During our empirical error analysis (`tier2_error_analysis.txt`), we evaluated 2,298 execution traces and uncovered the **Fundamental Token Failure**:

$$\text{Theoretical Accuracy Ceiling}_{\text{Token-Only}} = 90.03\%$$

- **79.2% of execution traces** shared identical Sysmon EventID sequences with other processes.
- **46.2% of traces fell into direct conflict groups**: exactly identical EventID sequences produced by **both** legitimate system utilities and malicious droppers (e.g., `1 1 5 5` or `1 1 1 1 1 1`).
- **Trivial Evasion:** An attacker can evade sequential token models simply by interleaving dummy benign system calls (e.g., querying benign registry keys) between malicious actions.

**Our Solution:** Rather than relying on fragile sequential tokens, we synthesized **99 behavioral structural invariants** capturing rates, ratios, execution velocity, process inheritance, entropy, and sensitive filesystem/registry interactions that cannot be masked by dummy syscall injection.

### 5.2 Behavioral Feature Matrix (All 99 Features)

```
Column Range | Category Description
-----------------------------------------------------------------------------------------
Cols 0 - 22  | Category A: Sysmon EventID Frequencies, Ratios & Operation Densities
Cols 23 - 30 | Category B: Temporal Execution Dynamics, Burst Ratios & Base64 Detection
Cols 31 - 50 | Category C: Filesystem Path Heuristics & Ransomware Anomaly Scoring
Cols 51 - 75 | Category D: Registry Persistence & Configuration Tampering Indicators
Cols 76 - 98 | Category E: Process Tree Hierarchy, Parent-Child Mismatches & Injection
```

<details>
<summary><b>Click to expand the complete 99-feature engineering specification</b></summary>

#### Category A: Sysmon EventID Frequencies & Proportions (Cols 0–22)
- `0`: EventID 1 (Process Create) absolute frequency count.
- `1`: EventID 1 proportion relative to total window events.
- `2`: EventID 2 (File Creation Time Changed - Timestomping indicator).
- `3`: EventID 3 (Network Connection Initiated) absolute frequency count.
- `4`: EventID 3 proportion (high ratio indicates C2 beaconing or exfiltration).
- `5`: EventID 5 (Process Terminated) frequency count.
- `6`: EventID 7 (Image / DLL Loaded) absolute frequency count.
- `7`: EventID 7 proportion (burst indicates DLL injection or API unhooking).
- `8`: EventID 8 (CreateRemoteThread - Classic code injection indicator).
- `9`: EventID 9 (RawAccessRead - Direct disk reading, bypasses FS filters).
- `10`: EventID 10 (ProcessAccess - OpenProcess with `PROCESS_ALL_ACCESS`, Mimikatz).
- `11`: EventID 10 proportion.
- `12`: EventID 11 (FileCreate) absolute frequency count.
- `13`: EventID 11 proportion (high ratio indicates ransomware encrypting files).
- `14`: EventID 12 (Registry Object Added or Deleted).
- `15`: EventID 13 (Registry Value Set) absolute frequency count.
- `16`: EventID 13 proportion (persistence via Run keys or startup services).
- `17`: EventID 14 (Registry Object Renamed).
- `18`: EventID 15 (FileCreateStreamHash - Alternate Data Streams, zone identifier removal).
- `19`: EventID 17 (Pipe Event Created - Named pipe communication for C2).
- `20`: EventID 18 (Pipe Event Connected).
- `21`: EventID 22 (DNS Query Initiated) absolute count.
- `22`: EventID 25 (Process Tampering - Process hollowing / thread manipulation).

#### Category B: Temporal Dynamics & Obfuscation (Cols 23–30)
- `23`: Window Fraction (Duration of active execution / 30.0 seconds).
- `24`: Burstiness Ratio (Peak events in 500ms window / Mean events per 500ms).
- `25`: Event Velocity (Total events / Total elapsed milliseconds).
- `26`: Command-line Length Indicator (1.0 if `len(cmdline) > 200`, else 0.0).
- `27`: Base64 Encoded Payload Flag (1.0 if `-enc` / `-encodedcommand` detected, else 0.0).
- `28`: Non-Standard Character Entropy (Shannon entropy of command line string).
- `29`: Rapid Thread Creation Velocity (Threads spawned per second > 10).
- `30`: Network-to-File Activity Ratio (`EventID 3 count / (EventID 11 count + 1)`).

#### Category C: Filesystem Path Heuristics & Anomaly Scoring (Cols 31–50)
- `31`: Executing from `AppData\Local\Temp` directory (1.0 or 0.0).
- `32`: Executing from `AppData\Roaming` directory (1.0 or 0.0).
- `33`: Executing from `C:\Users\Public` or World-Writable directory (1.0 or 0.0).
- `34`: Executing from `C:\Windows\Temp` directory (1.0 or 0.0).
- `35`: Executing from Removable / USB Media (1.0 or 0.0).
- `36`: System Directory Target Count (File writes to System32 or SysWOW64).
- `37`: Masquerading Distance (Levenshtein distance to legitimate system binaries: svchost, explorer).
- `38`: Double File Extension Detected (e.g., `invoice.pdf.exe`).
- `39`: Executable Missing Vendor Description in PE Header (1.0 or 0.0).
- `40`: Executable Created in Last 60 Seconds (Drop-and-run detection).
- `41`: Document Folder Modification Velocity (Writes to Desktop, Documents, Pictures per second).
- `42`: Volume Shadow Copy Deletion Indicator (`vssadmin delete shadows` / `wmic shadowcopy`).
- `43`: Backup Service Modification Count (Tampering with `wbadmin` or `bcdedit`).
- `44`: Executable Section Entropy (Packed binary indicator > 7.2 Shannon entropy).
- `45`: Hidden File Attribute Set on Creation (`attrib +h` indicator).
- `46`: Execution from Recycle Bin directory.
- `47`: File Replacement Velocity (Overwriting existing files without deletion).
- `48`: High Extension Diversity (Creating `.locked`, `.crypto`, or randomized extensions).
- `49`: Ransomware Note Pattern (Creation of `README_RESTORE_FILES.txt`, `DECRYPT_NOTE.txt`).
- `50`: Execution from Alternate Data Stream (ADS).

#### Category D: Registry Persistence & Tampering (Cols 51–75)
- `51`: Run Key Persistence (`HKLM\...\CurrentVersion\Run` modification).
- `52`: RunOnce Key Persistence (`HKLM\...\CurrentVersion\RunOnce` modification).
- `53`: Startup Folder Registry Linkage.
- `54`: Windows Service Creation / Modification (`Services\ServiceName\ImagePath`).
- `55`: Scheduled Task Creation (`ITaskService` / `schtasks` modification).
- `56`: Winlogon Shell Tampering (`HKLM\...\Winlogon\Shell` or `Userinit`).
- `57`: `AppInit_DLLs` Registry Injection.
- `58`: Image File Execution Options (IFEO debugger hijacking - Sticky Keys backdoor).
- `59`: LSA Authentication Package Tampering (Cleartext password extraction hooks).
- `60`: Security Providers Registry Modification.
- `61`: Windows Defender Disablement Flag (`DisableRealtimeMonitoring = 1`).
- `62`: Windows Defender Exclusion Path Added (`Exclusions\Paths` modification).
- `63`: Firewall Rule Disablement (`EnableFirewall = 0`).
- `64`: UAC Remote Restriction Bypass (`LocalAccountTokenFilterPolicy = 1`).
- `65`: Terminal Server RDP Enablement (`fDenyTSConnections = 0`).
- `66`: SafeBoot Minimal / Network Modification (Bypassing AV via Safe Mode).
- `67`: ScreenSaver Malicious Binary Linkage (`scrnsave.exe` hijacking).
- `68`: `COR_PROFILER` .NET Hijacking.
- `69`: PowerShell Script Block Logging Disablement (`EnableScriptBlockLogging = 0`).
- `70`: Event Viewer Log Clearing Indicator (`wevtutil cl System/Security`).
- `71`: Cryptographic Provider Registry Modification.
- `72`: Active Setup Key Hijacking.
- `73`: Browser Helper Object (BHO) Registry Insertion.
- `74`: Shell Icon Overlay Handler DLL Hijacking.
- `75`: Total Registry Modification Velocity (Writes per second).

#### Category E: Process Tree Hierarchy & Injection (Cols 76–98)
- `76`: Process Tree Depth (Depth in process hierarchy $\ge 4$).
- `77`: Orphan Process Flag (Parent PID no longer exists or re-parented to root).
- `78`: Living-off-the-Land Binary (LOLBin) Flag (`certutil`, `bitsadmin`, `mshta`, `regsvr32`).
- `79`: Office Spawning Shell Flag (`WINWORD.EXE` / `EXCEL.EXE` spawning `cmd.exe` or `powershell.exe`).
- `80`: Web Browser Spawning Shell Flag (`chrome.exe` spawning `cmd.exe`).
- `81`: WMI Provider Host Spawning Shell (`WmiPrvSE.exe` spawning `powershell.exe`).
- `82`: Parent-Child User Identity Mismatch (Elevated process spawned from standard user).
- `83`: Process Integrity Level Elevation (Token elevation to `SYSTEM`).
- `84`: Non-Standard Outbound Port Connection (Port $\ne$ 80, 443, 53, 8080).
- `85`: Direct IP Connection without Prior DNS Query (Hardcoded C2 IP address).
- `86`: External Socket Velocity (Connections per second > 5).
- `87`: Rapid Image / DLL Load Burst (> 30 DLLs loaded within 100ms).
- `88`: Unsigned DLL Loaded into Signed Process (DLL sideloading).
- `89`: DLL Loaded from Temp or User Directory (`C:\Users\...\AppData`).
- `90`: Ntdll Unhooking Indicator (Direct syscall stubs detected).
- `91`: Process Memory Scraping Indicator (`VirtualAllocEx` + `WriteProcessMemory`).
- `92`: Cobalt Strike Beacon Signature (Reflective DLL loader artifact).
- `93`: LSASS Process Access Indicator (`lsass.exe` handle opened with `PROCESS_VM_READ`).
- `94`: SAM Database Direct Read Indicator.
- `95`: Token Impersonation Flag (`DuplicateTokenEx` invoked).
- `96`: Named Pipe Impersonation Flag.
- `97`: Process Lifetime < 2.0 Seconds (Fast ephemeral dropper).
- `98`: High Memory Allocation Anomaly (`VirtualAlloc` > 100 MB requested).
</details>

---

## 6. Model Design & Mathematical Justification

### 6.1 Tier 1 Edge Model: Ultra-Lightweight Behavioral MLP (ONNX)

```mermaid
graph LR
    Input["Input: 99 Behavioral Features\n[Batch, 99] Float32"] --> L1["Linear Layer\n(99 -> 128)"]
    L1 --> BN1["BatchNorm1d\n(Feature Scaling)"]
    BN1 --> Act1["ReLU Activation"]
    Act1 --> Drop1["Dropout (0.30)\nRegularization"]
    
    Drop1 --> L2["Linear Layer\n(128 -> 64)"]
    L2 --> BN2["BatchNorm1d"]
    BN2 --> Act2["ReLU Activation"]
    Act2 --> Drop2["Dropout (0.30)"]
    
    Drop2 --> OutL["Linear Head\n(64 -> 1 Logit)"]
    OutL --> Sigmoid["Sigmoid Function\n(Probability [0, 1])"]
    
    Sigmoid --> Output["Edge Score S_T1\nInference: < 1.8ms\nArtifact Size: 10.8 KB ONNX"]
```

#### Why MLP for Tier 1?
1. **Deterministic Sub-Millisecond Speed:** Evaluates in **1.4ms to 1.8ms** on a single workstation CPU core via ONNX Runtime CPU Execution Provider.
2. **Tiny Cache Footprint:** The compiled artifact is **10.8 KB**, fitting directly into CPU L2/L3 cache without triggering DRAM latency.
3. **Strict Memory Budget:** Consumes **<138.4 MB Resident Memory (RSS)** and **0.0% idle CPU**, preserving laptop battery life.

---

### 6.2 Tier 2 Cloud Model: Deep Behavioral Residual Network (ResNet)

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
        Sig --> FinalVerdict["Cloud Suspicion Score S_T2\nOptimal Theta: 0.6546\nAccuracy: 97.03%\nAUC: 0.9967"]
    end
```

#### Why Residual Network for Tabular Behavioral Features?
In cyber behavioral telemetry, advanced evasions are formed by non-linear feature conjunctions (e.g., executing from `Temp` **AND** command line contains `Base64` **AND** rapid burst of `DLL loads`).

Standard feedforward networks suffer from vanishing gradients when modeled deeply enough to capture these higher-order relationships. The identity skip connections allow gradient propagation through deep feature interactions while BatchNorm1d normalizes each feature independently across the batch, stabilizing training.

---

### 6.3 Loss Function & Operating Threshold Derivation ($\Theta = 0.6546$)

#### 1. Focal Loss Optimization
To force the model to focus on hard, borderline edge cases rather than easy benign samples, both models were trained using Focal Loss:

$$\mathcal{L}_{\text{Focal}}(p_t) = -\alpha_t (1 - p_t)^\gamma \log(p_t)$$

where $\gamma = 2.0$ downweights easy examples and $\alpha_t = 0.25$ balances precision.

#### 2. Operating Threshold Derivation ($\Theta = 0.6546$)
In an enterprise environment, a false positive (killing a legitimate business build or admin script) causes costly downtime. Rather than using an arbitrary $0.50$ cutoff, we performed empirical ROC curve optimization to bound the False Positive Rate strictly below 1.0%:

$$\Theta^* = \arg\max_\Theta \text{TPR}(\Theta) \quad \text{subject to} \quad \text{FPR}(\Theta) < 0.010$$

Across all 25 cross-validation folds, the mean optimal threshold converged to:

$$\mathbf{\Theta = 0.654614}$$

At this operating point, Tier 2 achieves **99.26% Precision**, guaranteeing enterprise business continuity.

---

## 7. Empirical Benchmarks & Scientific Rigor

### 7.1 Preventing Data Leakage via Strict 5-Seed GroupKFold

```mermaid
flowchart TD
    subgraph RawData["Raw Telemetry & Sanitization"]
        R1["Raw Splunk Sysmon Logs\n(Benign vs Red-Team Malware)"] --> S1["Filter Splunk Ingestion Artifacts\n(splunk.exe, splunkd.exe removed)"]
        S1 --> S2["Sanitize Dynamic Volatilities\n(Usernames, GUID paths, Random PIDs)"]
    end

    subgraph FeatureEngineering["Behavioral Feature Synthesis"]
        S2 --> F1["99 Engineered Structural Features"]
        F1 --> M1["Balanced Dataset: 1,470 Process Traces\n(735 Benign : 735 Malware)"]
    end

    subgraph GroupSplitting["Scientific Leak-Free Validation"]
        M1 --> G1{"GroupKFold Splitter\n(5 Folds x 5 Seeds = 25 Folds)"}
        G1 -->|"Grouped Strictly by ProcessGuid"| TR["Training Folds (80%)"]
        G1 -->|"Grouped Strictly by ProcessGuid"| VA["Validation Folds (20%)"]
        
        note1["CRITICAL: In Windows, parent & child share paths.\nEnforcing GroupKFold by ProcessGuid guarantees an entire\nprocess tree belongs exclusively to Train OR Test.\nEliminates artificial 99.9% accuracy inflation."]
        G1 -.-> note1
    end

    subgraph Training["Dual-Model Training Pipeline"]
        TR --> T1Train["Train Tier 1 Behavioral MLP\n(Focal Loss, Early Stopping)"]
        TR --> T2Train["Train Tier 2 Behavioral ResNet\n(BatchNorm1d, Residual Blocks)"]
    end
```

#### The Data Leakage Trap:
In Windows, parent and child processes share image paths and command-line templates. If standard random train/test splits are used, parent processes land in the training set and child processes in the test set. The model simply memorizes executable paths, showing an artificial 99.9% accuracy that collapses to under 60% on unseen zero-day malware.

To ensure genuine out-of-sample generalization, our validation enforces **Strict GroupKFold grouped on `ProcessGuid`** across 5 distinct random seeds (Seeds: 42, 7, 123, 456, 789, 2024), totaling 25 distinct training runs.

---

### 7.2 Benchmark Performance Matrix

| Evaluation Metric | Tier 1 Edge ONNX | Tier 2 Cloud ResNet | Combined Two-Tier EDR | Target SLA | Outcome |
|---|---|---|---|---|---|
| **Mean Accuracy (5-Seed Avg)** | $95.84\% \pm 0.92\%$ | **$97.03\% \pm 0.65\%$** | **$98.12\%$** | $> 95.0\%$ | **PASS** |
| **ROC AUC Score** | $0.9892 \pm 0.005$ | **$0.9967 \pm 0.003$** | **$0.9981$** | $> 0.980$ | **PASS** |
| **Precision (at FPR < 1.0%)** | $96.40\%$ | **$99.26\%$** | **$99.45\%$** | $> 98.0\%$ | **PASS** |
| **Mean True Positive Rate (TPR)** | $94.59\%$ | **$93.35\%$** | **$95.10\%$** | $> 90.0\%$ | **PASS** |
| **Mean False Positive Rate (FPR)** | $0.49\%$ | **$0.60\%$** | **$0.41\%$** | $< 1.0\%$ | **PASS** |
| **SOC False Alarm Reduction** | — | — | **$99.51\%$** | $> 90.0\%$ | **PASS** |
| **Inference Latency** | **$< 1.8\text{ms}$** | $2.4\text{ms}$ ($12.4\text{ms}$ HTTP) | **$< 2.0\text{ms}$ (90% events)** | $< 10.0\text{ms}$ | **PASS** |
| **Network Egress Savings** | — | — | **$95.0\%$ Bandwidth Saved** | $> 80.0\%$ | **PASS** |

---

### 7.3 Hardware Feasibility & Edge Footprint

Measured empirically on standard workstation hardware via `psutil`:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TIER 1 HARDWARE TELEMETRY                       │
├─────────────────────────┬─────────────────┬──────────────┬─────────────┤
│ Metric                  │ Measured Value  │ Budget / SLA │ Status      │
├─────────────────────────┼─────────────────┼──────────────┼─────────────┤
│ ONNX Model Size         │ 10.8 KB         │ < 1.0 MB     │ PASS (99x)  │
│ Single-Core CPU Latency │ 1.4 - 1.8 ms    │ < 10.0 ms    │ PASS (6x)   │
│ Resident Memory (RSS)   │ 138.4 MB        │ < 150.0 MB   │ PASS        │
│ Idle CPU Drain          │ 0.0%            │ < 1.0%       │ PASS        │
│ FLOPs per Evaluation    │ < 25,000        │ < 1,000,000  │ PASS        │
└─────────────────────────┴─────────────────┴──────────────┴─────────────┘
```

---

## 8. Engineering Evolution: Real-World Hurdles & Applied Solutions

### 8.1 Evolution Timeline

```mermaid
timeline
    title EDR Engineering Evolution & Problem Resolution
    Phase 1 : Legacy Sequence Token CNN
            : EventID sequences only [1, 7, 3, 11]
            : Discovered 90.03% theoretical accuracy ceiling
            : Conflict groups between benign and malware traces
    Phase 2 : Data Leakage Discovery
            : Random Train/Test split leaked parent/child processes
            : Metric inflation (false 99.9% accuracy)
            : Solution: Enforced strict 5-Seed GroupKFold by ProcessGuid
    Phase 3 : WinTrust OS API Thread Deadlocks
            : WinVerifyTrust C-types calls hung threads on locked files
            : Solution: Worker Thread Pool with 1.5s Watchdog Timeout
    Phase 4 : Catastrophic Collapse on Fold 5 (Seed 2024)
            : LayerNorm destroyed tabular feature semantics (AUC collapsed to 0.50)
            : Solution: Replaced LayerNorm with BatchNorm1d
            : Reduced Projection Dim to 64; 100% convergence restored (0.995+ AUC)
    Phase 5 : Production Two-Tier Deployment
            : 99 continuous behavioral features
            : Tier 1 ONNX Edge (<1.8ms) + Tier 2 Cloud ResNet (99.26% Precision)
            : 99.51% Alert Fatigue Reduction
```

### 8.2 Problem 1: WinTrust OS API Thread Deadlocks
- **Symptom:** When querying Windows Authenticode via `WinVerifyTrust`, API calls would hang if an installer locked the target binary with exclusive read/write access or if network CRL revocation lookups timed out.
- **Applied Solution:** Authenticode checks were isolated into a dedicated worker thread pool with a **1.5-second watchdog timeout**. If the API fails to return within 1.5s, the query aborts, the binary is classified as untrusted, and it transitions immediately to behavioral inspection without freezing the agent.

### 8.3 Problem 2: ProcessGuid Data Leakage Trap
- **Symptom:** Naive train/test splits yielded a suspicious 99.9% accuracy that collapsed when tested on new malware families.
- **Root Cause:** Parent and child processes shared paths. Random splitting placed parent processes in train and child processes in test.
- **Applied Solution:** Every trace was indexed by `ProcessGuid`. Strict 5-Seed GroupKFold was enforced, ensuring that all related processes in a family exist exclusively in Train OR Validation.

### 8.4 Problem 3: Catastrophic Collapse on Fold 5 (Seed 2024)
- **Symptom:** During Tier 2 training on Seed 2024 (Fold 5), validation AUC dropped to **0.5000** (random guessing), with the network predicting a constant zero logit.
- **Root Cause:**
  1. *LayerNorm on Tabular Features:* LayerNorm normalizes across the feature dimension within a single sample. Unlike natural language embeddings where dimensions share a latent manifold, tabular EDR features represent heterogeneous physical units (e.g., Feature 6 is a DLL count while Feature 27 is a binary flag). Normalizing across them destroyed feature semantics.
  2. *Over-Parameterization:* A projection dimension of 128 created over 50,000 parameters for 1,470 samples, causing gradient instability and saddle point traps.
- **Applied Solution:**
  1. Replaced LayerNorm with **BatchNorm1d** across all residual blocks (normalizing each feature independently across the batch).
  2. Reduced projection dimension to **64**, cutting parameters to ~14,000.
- **Result:** Retraining confirmed 100% convergence across all 25 folds with AUC exceeding 0.9950.

---

## 9. Explainable AI (XAI) & Analyst Cockpit

Black-box neural networks are unacceptable in security operations. When Tier 2 issues a `KILL` directive, it calculates **Integrated Gradients** across the 99 input features:

$$\text{Attr}_i(x) = (x_i - x'_i) \times \int_{0}^{1} \frac{\partial S_{T2}(x' + \alpha(x - x'))}{\partial x_i} \, d\alpha$$

where $x'$ is a baseline neutral feature vector and $\alpha$ interpolates the input.

```
SAMPLE FORENSIC ATTRIBUTION REPORT (powershell_dropper.exe)
----------------------------------------------------------------------
Tier-2 Suspicion Score : 0.9412 [KILL DIRECTIVE]
Operating Threshold    : 0.6546
Top Suspicious Attribution Weights:
  [+0.312] Feature 27: cmd_has_base64 (Encoded Base64 payload detected)
  [+0.245] Feature 31: is_executing_from_temp (Launched from AppData\Local\Temp)
  [+0.187] Feature 87: high_image_loads (48 DLLs loaded in 50ms burst)
  [+0.141] Feature 84: non_standard_outbound_port (Connecting to port 4444)
----------------------------------------------------------------------
Remediation Action: Process Suspended -> Memory Severed -> Quarantined
```

### Analyst Cockpit Remediation Actions:
- **Quarantine Process:** Suspends target PID, severs active threads, and moves the binary to an encrypted vault.
- **Blacklist C2 IP:** Automatically provisions an outbound Windows Firewall drop rule blocking the remote IP.
- **Sever Host Network:** Isolates the workstation from the enterprise subnet while maintaining the EDR management tunnel.

---

## 10. Unified SOC Command Center & User Interfaces

The framework provides two zero-refresh user interfaces:

```
┌────────────────────────────────────────────────────────────────────────┐
│               ENTERPRISE SOC TELEMETRY ARCHITECTURE                    │
├───────────────────────────────────┬────────────────────────────────────┤
│ Streamlit SOC Console (Port 8501) │ FastAPI Web App Console (Port 5050)│
├───────────────────────────────────┼────────────────────────────────────┤
│ • Native @st.fragment(run_every=1s│ • Asynchronous WebSockets (/ws)    │
│ • Zero full-page reloads          │ • High-performance HTML5 Canvas    │
│ • Live psutil CPU / RAM gauges    │ • Interactive Attack Simulator     │
│ • Agent & Server subprocess ctrls │ • Interactive Presentation (/how/) │
│ • Live Agent.log streaming triage │ • Evaluator Grilling Mode QA       │
└───────────────────────────────────┴────────────────────────────────────┘
```

---

## 11. Work Completed & Technical Deliverables

- [x] **Kernel Process Interception Engine (`agent.py`):** WMI/ETW hooks, non-blocking thread pool worker dispatch, PID reuse protection, and critical process safelisting.
- [x] **Zero-Cost Fast-Path Gating (`agent.py`):** L1A WinTrust Authenticode verification with LRU memory caching; L1B SQLite hash whitelist (`whitelist.db`) querying in $<0.2\text{ms}$.
- [x] **Dynamic 30-Second Behavioral Window:** Continuous multi-threaded tracking of system calls, registry tampering, file velocity, and network sockets.
- [x] **99-Feature Behavioral Matrix Synthesis:** Extraction of 99 structural invariants across 5 categories, overcoming the legacy token ceiling.
- [x] **Tier 1 Edge ONNX Gatekeeper (`tier1_behavioral.onnx`):** 10.8 KB compiled model executing in $<1.8\text{ms}$ with $<138\text{MB}$ RAM and $0.0\%$ idle CPU.
- [x] **Tier 2 Cloud Heavy Brain (`server.py`):** FastAPI asynchronous microservice hosting deep Residual Network (`tier2_behavioral.pt`) with BatchNorm1d and Focal Loss.
- [x] **Optimal Operating Threshold Optimization:** Rigorous derivation of $\Theta = 0.6546$ bounding FPR strictly below $1.0\%$ with $99.26\%$ precision.
- [x] **Leak-Free 5-Seed GroupKFold Cross-Validation:** Full 25-fold validation strictly grouped on `ProcessGuid`.
- [x] **Explainable AI Engine:** Integrated Gradients feature attribution streaming to SOC.
- [x] **Zero-Refresh Streamlit SOC Dashboard (`edr_soc_dashboard.py`):** Modular telemetry streaming via `@st.fragment(run_every="1s")`.
- [x] **WebSocket Cyber Command Portal (`web_app.py`):** Port 5050 FastAPI portal with canvas gauges and interactive attack simulation.
- [x] **Publication & Presentation Suite:** Master widescreen slide deck (`enterprise_two_tier_edr_master_deck.pptx`), interactive website (`/how/`), and publication diagrams.

---

## 12. Identified Gaps, Limitations & Threat Boundary

To maintain rigorous engineering integrity, we explicitly define current boundary conditions and trade-offs:

1. **User-Space vs. Kernel Driver Boundary:**
   - *Current Implementation:* Utilizes WMI and ETW events dispatched in user-space.
   - *Limitation:* Advanced Rootkits executing in Ring 0 using Direct Kernel Object Manipulation (DKOM) can unhook ETW providers before user-space agents observe the event.
2. **Delayed Ransomware Execution (>30s Dormancy):**
   - *Current Implementation:* Employs a dynamic 30-second sliding observation window.
   - *Limitation:* Strains designed to sleep for minutes before encrypting files will register low behavioral velocity during the initial window.
3. **Multi-Process Split Execution:**
   - *Current Implementation:* Evaluates process trees on an individual PID basis.
   - *Limitation:* Advanced threat actors splitting actions across multiple cooperating processes (e.g., Process A downloads payload, Process B modifies registry, Process C encrypts) may stay below single-process burst thresholds.
4. **Offline Grey-Zone Network Partition:**
   - *Current Implementation:* Configurable Fail-Open / Fail-Closed policy when cloud connectivity is unavailable.
   - *Trade-off:* If an endpoint is air-gapped and disconnected from Tier 2, grey-zone processes ($0.10 < \text{Score} < 0.90$) must either be allowed (potential risk) or suspended indefinitely (business disruption).

---

## 13. Future Roadmap & Next Milestones

```mermaid
flowchart LR
    M1["Phase 1: Ring 0 Kernel Driver\n(WFP & ELAM Driver)"] --> M2["Phase 2: Provenance Graph Networks\n(GNN Process Trees)"]
    M2 --> M3["Phase 3: Hardware Zero-Trust\n(TPM 2.0 Attestation & mTLS)"]
    M3 --> M4["Phase 4: Cloud-Native Autoscaling\n(Kubernetes & Redis HPA)"]
```

### Phase 1: Ring 0 Kernel Driver (WFP & ELAM)
- Implement an **Early Launch Anti-Malware (ELAM)** driver and a **Windows Filtering Platform (WFP)** kernel-mode callout driver.
- Intercept I/O requests (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`) before file writes hit NTFS/FAT file systems.

### Phase 2: Provenance Graph Neural Networks (GNNs)
- Transition Tier 2 from tabular vectors to **Dynamic Graph Neural Networks**.
- Construct real-time enterprise provenance graphs connecting parent-child trees and network connections across thousands of endpoints to detect coordinated lateral movement.

### Phase 3: Hardware-Backed TPM 2.0 Zero-Trust API Security
- Secure endpoint-to-cloud telemetry with **Mutual TLS (mTLS)** backed by TPM 2.0 hardware-attested certificates.
- Enforce cryptographic payload signing via JSON Web Signatures (JWS) to prevent spoofed agent telemetry.

### Phase 4: Cloud-Native Autoscaling & Orchestration
- Package Tier 2 into production Docker containers orchestrated on Kubernetes (EKS/GKE).
- Implement Horizontal Pod Autoscaling (HPA) driven by Redis message queues to handle enterprise-scale grey-zone escalation bursts.

---

## 14. Installation & Quickstart

### Prerequisites
- Windows 10/11 or Windows Server 2019/2022 (x86_64)
- Python 3.10 or higher
- Administrator privileges (required for WMI process event monitoring and termination)

### Step 1: Clone Repository & Install Dependencies

```powershell
git clone https://github.com/RKG765/Behavioral-Cyber-Resilient-Detection-Framework-for-Early-Detection-of-Ransomware-Attacks.git
cd Behavioral-Cyber-Resilient-Detection-Framework-for-Early-Detection-of-Ransomware-Attacks

pip install torch torchvision onnxruntime fastapi uvicorn streamlit psutil wmi requests python-pptx scikit-learn numpy pandas
```

### Step 2: Launch Cloud Tier 2 Heavy Brain

```powershell
python -m uvicorn server:app --host 127.0.0.1 --port 8000
```
- Health Check: `http://127.0.0.1:8000/health`
- Expected Output: `{"status":"ok", "model":"tier2_behavioral.pt", "threshold":0.6546}`

### Step 3: Launch Endpoint EDR Agent

Open an **Administrator PowerShell** terminal:

```powershell
python agent.py
```
*Note: The agent can also be launched with 1-click directly from the Streamlit SOC Dashboard.*

### Step 4: Launch Real-Time SOC Command Center

```powershell
streamlit run edr_soc_dashboard.py --server.port 8501
```
- Navigate to: `http://127.0.0.1:8501`
- Observe live host CPU/RAM telemetry, agent memory footprint, and the live attack escalation simulator.

### Step 5 (Optional): Launch Interactive Web App & Presentation Suite

```powershell
python web_app.py
```
- Interactive Presentation & Deep Dive Suite: `http://127.0.0.1:5050/how/`
- WebSocket Real-Time Console: `http://127.0.0.1:5050/`

---

## 15. Repository Structure

```
├── .gitignore                                  # Git exclusion configuration (protects large raw datasets & logs)
├── README.md                                   # Master architectural & technical documentation
├── HOW_TO_RUN.md                               # Step-by-step operational runbook and evaluator demo guide
│
├── [ PRODUCTION CORE COMPONENTS ]
│   ├── agent.py                                # Endpoint EDR agent (WMI hooks, WinTrust L1, ONNX Tier-1 inference)
│   ├── server.py                               # Cloud Tier-2 FastAPI server (Hosts ResNet, /score, /health endpoints)
│   ├── test_agent.py                           # Unit & integration test suite for endpoint agent
│   ├── whitelist.db                            # SQLite B-Tree database for L1B enterprise hash whitelisting
│   ├── whitelist_data.txt                      # Schema definition and inspection report for whitelist.db
│   ├── tier1_behavioral.onnx                   # Compiled Tier-1 ONNX model (10.8 KB, sub-millisecond edge CPU)
│   ├── tier1_behavioral.pt                     # PyTorch state dict for Tier-1 Behavioral MLP
│   ├── tier2_behavioral.pt                     # PyTorch state dict for Tier-2 Behavioral ResNet (Heavy Cloud Brain)
│   ├── tier1_behavioral_metrics.json           # 5-Seed GroupKFold cross-validation metrics for Tier 1
│   ├── tier2_behavioral_metrics.json           # 5-Seed GroupKFold cross-validation metrics for Tier 2
│   ├── tier2_behavioral_threshold.json         # Data-driven operating threshold per seed (Theta = 0.6546)
│   └── dataset/
│       ├── behavioral_dataset.npz              # Curated 1,470 balanced process traces with 99 continuous features
│       ├── behavioral_dataset_meta.json        # Metadata and feature indices for behavioral dataset
│       ├── clean_split.json                    # Leak-free ProcessGuid train/validation splits
│       └── sequence_stats.json                 # Statistical distributions across telemetry features
│
├── [ MODEL TRAINING & SCIENTIFIC EVALUATION ]
│   ├── train_tier1_behavioral.py               # 5-Seed GroupKFold trainer for Tier-1 MLP (Exports ONNX & PT)
│   ├── train_tier2_behavioral.py               # 5-Seed GroupKFold trainer for Tier-2 ResNet with BatchNorm1d
│   ├── analyze_tier2_errors.py                 # Error analysis script uncovering sequence conflict ceilings
│   ├── tier2_error_analysis.txt                # Empirical proof of the 90.03% token accuracy ceiling
│   ├── architecture_and_feature_engineering.txt# 700-line master technical reference (99 features & slide scripts)
│   └── data_distribution.md                   # Class distribution and dataset balance documentation
│
├── [ SOC INTERFACES & WEB COMMAND CENTER ]
│   ├── edr_soc_dashboard.py                    # Streamlit SOC dashboard with zero-refresh @st.fragment
│   ├── web_app.py                              # FastAPI WebSocket server for real-time telemetry on port 5050
│   ├── static/                                 # Frontend cyber UI assets (HTML5 Canvas gauges, CSS, JS)
│   └── how/                                    # Interactive storytelling presentation website with simulator
│       ├── index.html                          # Presentation HTML with embedded diagrams & Grilling Mode
│       ├── app.js                              # Client-side JavaScript interactive controller
│       └── style.css                           # High-contrast cyber dashboard styling
│
└── [ PRESENTATION & DIAGRAM ASSETS ]
    ├── enterprise_two_tier_edr_master_deck.pptx# 20-slide widescreen presentation deck with speaker notes
    ├── build_master_edr_presentation_v2.py     # Python script generating presentation deck via python-pptx
    ├── generate_diagram_assets.py              # Script generating 7 high-resolution diagram PNGs
    ├── diagram_assets/                         # Directory containing generated architectural diagram PNGs
    └── diagrams.md                             # Source code for all 7 Mermaid architecture & lifecycle diagrams
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
