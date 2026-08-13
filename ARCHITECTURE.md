# Architecture

The system architecture is strictly focused on Host-Based Intrusion Detection and Prevention (HIDS/IPS). 

## Host Data Flow

```text
Host Operating System
│
▼
[ Telemetry Sources ]
├── psutil (process polling)
└── Filesystem/OS commands (crontab, systemctl, config files)
│
▼
[ Detection Engine (HybridEngine) ]
├── Behavioral Features Extraction
└── Rule-Based Heuristics (The 7 Canonical Attacks)
│
▼
[ Threat Memory ]
├── 1st Occurrence: Log to memory dictionary
└── 2nd Occurrence: Forward to Response Engine
│
▼
[ Response Engine & Prevention ]
├── pkill (Memory Eater, Discovery Burst, Masquerading)
├── os.remove (Staging files, Systemd services)
└── Config Rewrite (Cron, Shell RC)
│
▼
[ Event Log ]
└── hids/data/event_log.json
│
▼
[ API Gateway (server.py) ]
└── Lightweight Flask server exposing event_log.json
│
▼
[ Dashboard (app.py) ]
└── Streamlit UI rendering Host IPS telemetry
```

## Core Components

### 1. Telemetry Collector (`hids/behavioral/collector.py`)
- Iterates over all active processes using `psutil`.
- Captures memory footprint, CPU percentage, command-line arguments, parent process, and file paths.

### 2. Hybrid Engine (`hids/behavioral/hybrid_engine.py`)
- Holds the explicit detection rules for the 7 canonical attacks.
- Maintains cooldown states to prevent alert spamming.
- Serves as the central orchestration loop.

### 3. Response Engine (`hids/response_engine.py`)
- A dispatch table mapping attack IDs (e.g., `shell_rc_persist`) to mitigation functions (e.g., `_prevent_shell_rc()`).
- Designed to be surgical: deleting only malicious lines in config files instead of indiscriminately destroying user data.

### 4. API Gateway (`server.py`)
- Replaces the legacy network ingress.
- Exposes endpoints (`/logs`, `/stats`) that simply read and serve the `event_log.json` to the frontend dashboard.

### 5. Dashboard (`app.py`)
- Streamlit application displaying real-time system resources and active biological OS threats mapped to MITRE.
