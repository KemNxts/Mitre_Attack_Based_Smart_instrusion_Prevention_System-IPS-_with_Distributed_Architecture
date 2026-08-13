# Next Steps & Prioritized Roadmap

Based on the completed architecture cleanup (which successfully removed obsolete network attacks, legacy ML, and successfully wired the Dashboard to the HIDS event logs), the following prioritized roadmap outlines the required steps to stabilize and harden the 7-attack system.

## 1. Fix Hardcoded Detection Paths
- **Action**: Refactor `_detect_memory_abuse` to dynamically identify suspicious high-memory Python processes without hardcoding the script name `dump.py` or the absolute user path `/home/khushal/bin/`.
- **Action**: Refactor `_detect_systemd_persistence` and `_detect_cron_persistence` to not explicitly rely on strings like `/home/khushal/bin/` or `persist_payload.sh`.
- **Outcome**: Ensures the detection engine works portably across different servers and usernames, catching dynamic payloads.

## 2. Improve Telemetry Reliability (Future-Proofing)
- **Action**: Acknowledge the current `psutil` polling limitation that misses sub-millisecond recon commands (Discovery Burst).
- **Future Integration**: Plan to integrate `auditd` or `eBPF` as a secondary telemetry source for event-driven process monitoring rather than interval polling.

## 3. Improve Persistent Storage
- **Action**: Replace the in-memory Python dictionaries used by `ThreatMemory` with a lightweight persistent database (e.g., SQLite or Redis) to ensure threat tracking and mitigation counts survive system reboots.

## 4. Centralized Distributed Architecture
- **Action**: While the dashboard currently queries the lightweight API gateway (`server.py`), convert `run_hybrid.py` into a true standalone agent that transmits its `event_log.json` telemetry over an encrypted REST/gRPC API to a remote central server.
