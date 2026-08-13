# Project State

## Exact Project Purpose
The purpose of this project is to be a Host-Based Intrusion Detection and Prevention System (HIDS/IPS) that specifically monitors, detects, and prevents 7 canonical MITRE ATT&CK host-based behaviors. It uses behavioral telemetry to adaptively score and respond to real attacks, rather than relying on static signatures.

## Final Seven-Attack Scope
The system's absolute scope is limited strictly to the following 7 real host-based attacks:
1. **Parent-Child Memory Eater** (T1496)
2. **Cron Persistence** (T1053.003)
3. **Systemd User Service Persistence** (T1543.002)
4. **Discovery Burst** (T1082 / T1057)
5. **Staging / Collection** (T1074.001)
6. **Process Masquerading** (T1036.005)
7. **Shell RC Persistence** (T1546.004)

*Note: All old generic/simulated network attacks (DoS, Brute Force, Web Attack, Port Scan, Bot) have been successfully removed.*

## Component Responsibilities & Data Flow
- **Data Collector (`psutil`)**: Polls the OS every 2-3 seconds to capture process state, relationships, and memory usage.
- **Hybrid Engine**: Analyzes the telemetry and file system state to detect the 7 canonical attacks using heuristics and thresholds.
- **Threat Memory**: Records detections. The first occurrence is logged to allow learning; the second occurrence triggers active mitigation.
- **Response Engine**: Executes surgical mitigation commands (e.g., `pkill`, `os.remove`, targeted text replacement).
- **API Gateway (`server.py`)**: A lightweight Flask server that serves `event_log.json` telemetry.
- **Dashboard (`app.py`)**: A Streamlit UI that reads from the API Gateway to display detected threats and system metrics.

## Detection Mechanisms & Telemetry
1. **Parent-Child Memory Eater**: `psutil` process snapshot -> monitors Python processes, RSS memory > 50MB, and child process trees.
2. **Cron Persistence**: Filesystem/OS command (`crontab -l`) -> parses lines for suspicious paths out of `/tmp` or `/home`.
3. **Systemd User Service Persistence**: Filesystem -> scans `~/.config/systemd/user/` for `.service` files containing suspicious `ExecStart` paths.
4. **Discovery Burst**: `psutil` process snapshot -> tracks history of short-lived recon commands tied to a specific PPID within a 15s window.
5. **Staging / Collection**: Filesystem -> monitors `/tmp` and `/home` for rapid creation (5+ within 15s) of archives.
6. **Process Masquerading**: `psutil` process snapshot -> compares `name`, `exe`, and `cmdline` against `MASQUERADE_NAMES` running from user-writable directories.
7. **Shell RC Persistence**: Filesystem -> parses `~/.bashrc`, `~/.zshrc`, etc., for malicious markers like `nc -e`.

## Threat Memory & Prevention
- **First Occurrence**: Logged in `ThreatMemory` (dictionary in memory). Emits a "DETECT_ONLY" event to `event_log.json`.
- **Second Occurrence**: Passes the alert dictionary to the `ResponseEngine`.
  - **Memory/Masquerade**: Recursively kills the process and children.
  - **Cron/Shell RC**: Parses the configuration file, removes only the malicious lines, and writes it back.
  - **Staging**: Recursively deletes the staged files.
  - **Discovery**: Kills the parent shell.
  - **Systemd**: Disables the service and deletes the file.

## Current Bugs & Technical Debt
- **Hardcoded Paths**: Logic includes hardcoded paths like `dump.py` and assumptions about `/home/khushal`.
- **In-Memory State**: Threat memory resets on restart; there is no persistent database.
- **Polling Limitations**: `psutil` polling every 3 seconds can miss sub-millisecond processes (a known gap for Discovery Burst).
