# RansomShield

**Real-Time Behavioral Ransomware Detection using Shannon Entropy and Anomaly Scoring**

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Build](https://img.shields.io/badge/Build-Maven-blue.svg)](https://maven.apache.org/)
[![GUI](https://img.shields.io/badge/GUI-JavaFX-brightgreen.svg)](https://openjfx.io/)
[![Database](https://img.shields.io/badge/Database-SQLite%20JDBC-lightgrey.svg)](https://sqlite.org/)
[![Testing](https://img.shields.io/badge/Tests-JUnit%205%20(27%20Passed)-success.svg)](https://junit.org/junit5/)
[![Defensive](https://img.shields.io/badge/Security-Safe%20Test%20Harness%20Only-blueviolet.svg)](#safety-principles--non-malware-guarantee)

---

## 1. Project Overview

Traditional signature-based antivirus solutions attempt to match known malware hashes or binary signatures. Modern zero-day ransomware frequently evades signature databases by mutating packers and compilers. **RansomShield** is a defensive, real-time cybersecurity platform that focuses entirely on **filesystem behavior**.

RansomShield monitors protected directories and detects suspicious patterns in real time:
- High file modification bursts and rates (files/sec)
- Rapid mass file modifications
- Traversal across multiple directories
- Sudden changes in file byte distribution and elevated **Shannon entropy**
- Suspicious extension renaming patterns (e.g. `.txt` &rarr; `.encrypted`)
- Multi-signal correlation into a **Threat Score (0 to 100)**

### Categorical Threat Levels
| Threat Score | Severity Level | UI Visual Indicator | System Action |
|:---:|:---:|:---:|:---|
| **0 – 29** | `NORMAL` | Green Badge | Baseline monitoring; no alerts. |
| **30 – 59** | `SUSPICIOUS` | Amber Badge | Anomaly logged; elevated observation. |
| **60 – 79** | `HIGH` | Orange Badge | Warning banner; security incident logged. |
| **80 – 100** | `CRITICAL` | Crimson Badge | Critical alert banner; incident logged to SQLite with remediation guidance. |

> **Critical False-Positive Defense Principle:**
> High entropy alone does **NOT** constitute ransomware. Legitimate encrypted ZIP archives, compressed videos, or cryptographic keys naturally exhibit high entropy. RansomShield strictly treats Shannon entropy as **one signal** among multiple behavioral indicators (burst rate, file volume, directory span, extension changes).

---

## 2. Architecture & Pipeline

RansomShield follows a decoupled, non-blocking pipeline:

```
[ Protected Directory ]
          │
          ▼
[ Java NIO WatchService (Recursive) ]
          │
          ▼
[ Event Collector (FileEvent) ]
          │
          ▼
[ Concurrent Bounded Queue (ArrayBlockingQueue) ]
          │
          ▼
[ Analysis Worker Pool (Multi-threaded ExecutorService) ]
       ┌──┴─────────────────────────┐
       ▼                            ▼
[ Shannon Entropy Engine ]   [ Sliding-Window Behavior Detector ]
(0.0 to 8.0 bits/byte)       (Rate, Files, Dirs, Rename Patterns)
       └──┬─────────────────────────┘
          ▼
[ Threat Score Engine (0–100 Weighted Model) ]
          │
          ▼
[ Risk Classifier (NORMAL / SUSPICIOUS / HIGH / CRITICAL) ]
          │
          ▼
[ Alert & Incident Manager (Deduplication & Correlation) ]
       ┌──┴────────────────────────┐
       ▼                           ▼
[ JavaFX Desktop Dashboard ]   [ SQLite Database (JDBC) ]
(Real-Time KPI & Event Feed)   (Incidents & Event Audit Trail)
```

### Architectural Pipeline Summary:
$$\text{Monitor} \longrightarrow \text{Capture} \longrightarrow \text{Queue} \longrightarrow \text{Analyze} \longrightarrow \text{Calculate Entropy} \longrightarrow \text{Analyze Behavior} \longrightarrow \text{Score} \longrightarrow \text{Alert} \longrightarrow \text{Display} \longrightarrow \text{Persist}$$

---

## 3. Core Modules

| Module / Class | Responsibilities |
|:---|:---|
| [`FileMonitor`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/monitor/FileMonitor.java) | Asynchronous directory watcher using `java.nio.file.WatchService`. Supports recursive directory registration, dynamic discovery of newly created subdirectories, and rename correlation. |
| [`EventQueueManager`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/monitor/EventQueueManager.java) | Thread-safe bounded `BlockingQueue<FileEvent>` separating fast filesystem event collection from slower entropy and I/O analysis. Tracks enqueued, dequeued, and dropped events. |
| [`EntropyCalculator`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/analysis/EntropyCalculator.java) | Computes byte-frequency distributions and Shannon entropy: $H(X) = -\sum P(x_i) \log_2 P(x_i)$. Uses streaming buffered reading with maximum sample guards to avoid memory exhaustion on large files. |
| [`BehaviorDetector`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/analysis/BehaviorDetector.java) | Maintains a sliding time window (default 5.0s). Computes modification rate (files/sec), affected file count, directory breadth, file states, and extension changes. |
| [`ThreatScoreEngine`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/analysis/ThreatScoreEngine.java) | Evaluates multi-factor weights (Entropy: up to 20 pts, Rate: up to 20 pts, Files: up to 20 pts, Directories: up to 10 pts, Pattern: up to 20 pts) into a score between 0 and 100. |
| [`AlertManager`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/alert/AlertManager.java) | Manages alert dispatch, deduplicates rapid alerts into unified incidents, and dispatches callbacks to listeners. |
| [`DatabaseManager`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/database/DatabaseManager.java) | SQLite database layer via JDBC (`jdbc:sqlite:ransomshield.db`). Employs parameterized `PreparedStatement`s across all tables: `incidents`, `file_events`, `monitored_directories`, and `application_settings`. |
| [`RansomwareSimulator`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/simulator/RansomwareSimulator.java) | Strict, sandboxed defensive test harness executing controlled harmless simulations **only** within the designated test directory. |
| [`DashboardView`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/ui/DashboardView.java) | JavaFX cybersecurity dashboard featuring KPI score cards, live event stream table, score factor progress bars, and threat diagnostics. |
| [`IncidentHistoryView`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/ui/IncidentHistoryView.java) | Incident history console with severity filtering, incident inspection modals, and status transitions (`DETECTED`, `ACKNOWLEDGED`, `RESOLVED`). |

---

## 4. Multi-Factor Threat Scoring Model

Total Maximum Score: **100 Points**

### 1. Shannon Entropy (0 – 20 Points)
- $\text{Entropy} < 6.0\text{ bits}$: **0 pts**
- $6.0 \le \text{Entropy} < 7.0\text{ bits}$: **5 pts**
- $7.0 \le \text{Entropy} < 7.5\text{ bits}$: **10 pts**
- $7.5 \le \text{Entropy} \le 8.0\text{ bits}$: **20 pts**

### 2. Modification Rate (0 – 20 Points)
- $< 2.0\text{ files/sec}$: **0 pts**
- $2.0 - 5.0\text{ files/sec}$: **5 pts**
- $5.0 - 15.0\text{ files/sec}$: **10 pts**
- $> 15.0\text{ files/sec}$: **20 pts**

### 3. File Volume Touched (0 – 20 Points)
- $1 - 5\text{ files}$: **0 pts**
- $6 - 20\text{ files}$: **5 pts**
- $21 - 100\text{ files}$: **10 pts**
- $> 100\text{ files}$: **20 pts**

### 4. Directory Traversal (0 – 10 Points)
- $1\text{ directory}$: **0 pts**
- $2\text{ directories}$: **3 pts**
- $3 - 4\text{ directories}$: **7 pts**
- $5+\text{ directories}$: **10 pts**

### 5. Operation Anomaly & Extension Patterns (0 – 20 Points)
- Normal modifications: **0 pts**
- Repeated create/modify cycle: **3 pts**
- Mass file rename/delete: **7 pts**
- Suspicious extension rename (e.g. `.encrypted`): **10 pts**
- Suspicious extension rename + mass burst: **20 pts**

---

## 5. Safe Controlled Simulator Modes

The simulator allows demonstrating and testing behavioral ransomware detection without using malware or real encryption:

1. **Mode 1: Normal Activity**
   - Modifies 2–3 files slowly with natural English text (~600ms delays).
   - Expected: `NORMAL` (Score: 0–10).
2. **Mode 2: High Entropy Single File (False-Positive Defense)**
   - Replaces 1 file with 8KB of high-entropy pseudorandom bytes ($H \approx 7.9$).
   - Demonstrates that entropy alone does **NOT** trigger critical alarms.
   - Expected: `NORMAL` (Score: 20/100).
3. **Mode 3: Mass File Modification**
   - Modifies 60+ files in rapid succession without encryption.
   - Tests burst modification rate and file volume heuristics.
   - Expected: `SUSPICIOUS` or `HIGH`.
4. **Mode 4: Suspicious Extension Rename**
   - Renames test files from `.txt` to `.encrypted`.
   - Tests extension mutation pattern detection.
   - Expected: Anomaly pattern flag.
5. **Mode 5: Multi-Directory Traversal**
   - Touches files across `Documents/`, `Images/`, `Reports/`, and `Projects/`.
   - Tests directory span anomaly detection.
6. **Mode 6: Combined Ransomware-like Simulation**
   - Full attack simulation: rapid modification burst + high-entropy bytes + multi-directory traversal + `.encrypted` renames.
   - Expected: `HIGH` or `CRITICAL` (Score: 75–95).

---

## 6. Safety Principles & Non-Malware Guarantee

RansomShield is an educational, defensive detection prototype and implements strict sandboxing:
- **Never executes malware:** No real ransomware payloads exist in the codebase.
- **Strict sandbox validation:** [`RansomwareSimulator.validateSafeTestDirectory()`](file:///c:/Users/Swayam%20Kumar/RansomShield/src/main/java/com/ransomshield/simulator/RansomwareSimulator.java#L34-L67) refuses to operate if target is null, the filesystem root (`C:\`, `/`), the user home directory (`~`), or system paths (`Windows`, `System32`, `Program Files`, `/etc`, `/usr`).
- **No external network access:** Never attempts to download malware or contact command-and-control servers.
- **No shell execution:** Does not launch shell or command-line processes.

---

## 7. Building & Running

### Prerequisites
- **JDK 21** or later (`java -version`)
- **Apache Maven 3.9+** (`mvn -version`)

### Compilation & Tests
Run all 27 unit and end-to-end integration tests:
```powershell
mvn clean test
```

### Packaging
Create the application JAR:
```powershell
mvn clean package -DskipTests
```

### Running the Desktop GUI
To start the JavaFX desktop application:
```powershell
mvn javafx:run
```
*(Or alternatively using the Exec plugin)*:
```powershell
mvn exec:java
```

---

## 8. Live Demonstration Walkthrough

Follow these steps for a live project demonstration:

1. **Launch RansomShield:** Run `mvn javafx:run`. The dark cybersecurity console opens with the monitoring status badge showing `MONITORING: STOPPED`.
2. **Select Monitored Directory:**
   - Click **[Select Directory]** and choose `./test-data` (or click **[Safe Test Simulator]** tab &rarr; **[Clear & Reset Test Data]** to automatically generate 100 test files across 4 folders).
3. **Start Monitoring:**
   - Click **[Start Monitoring]**. The status pill turns green: `MONITORING: RUNNING`. The Threat Score is 0 (`NORMAL`).
4. **Demonstrate Normal Activity:**
   - Switch to the **Safe Test Simulator** tab.
   - Select **Mode 1: Normal Activity**.
   - Click **[Run Selected Simulation]**.
   - Observe the **Live Threat Monitor** tab: 3 files are modified slowly. The Threat Score remains low (0–5, `NORMAL`).
5. **Demonstrate False-Positive Defense:**
   - In the Simulator tab, select **Mode 2: High Entropy Test (False-Positive Defense)**.
   - Click **[Run Selected Simulation]**.
   - Observe: 1 file is written with 7.9 bits/byte entropy.
   - The entropy factor card rises to 20 pts, but total score is **only 20/100**, remaining **`NORMAL`**.
   - *Key takeaway:* Entropy alone is not sufficient to declare ransomware.
6. **Demonstrate Ransomware-like Detection:**
   - In the Simulator tab, select **Mode 6: Combined Ransomware-like Simulation**.
   - Click **[Run Selected Simulation]**.
   - Observe the live dashboard:
     - Rapid events flood the live table feed with `.encrypted` renames.
     - Burst modification rate spikes (15–30 files/sec).
     - Directory span triggers multi-directory traversal points (4 directories).
     - Entropy spikes to ~7.8–7.9 bits/byte.
     - Threat Score surges to **`HIGH`** / **`CRITICAL`** (75–95).
     - The visual alert banner switches to Crimson: **`CRITICAL: RANSOMWARE-LIKE ACTIVITY DETECTED!`**
     - Detailed reasons populate the diagnostic breakdown panel.
7. **Inspect Incident History & Persistence:**
   - Switch to the **[Incident History]** tab.
   - Click **[Refresh]**.
   - View the logged security incident with score, affected files, rate, and reasons.
   - Double-click or click **[View Details]** to open the full audit report dialog.
   - Select the incident and click **[Acknowledge]** or **[Mark Resolved]** to observe state transitions.
8. **Reset Test Harness:**
   - In the Simulator tab, click **[Clear & Reset Test Data]** to safely wipe and repopulate a fresh, clean 100-file test dataset.
