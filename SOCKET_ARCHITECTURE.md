# Distributed Socket Architecture

This document describes the newly implemented telemetry forwarding layer that enables distributed deployment of the Smart HIDS across multiple nodes without compromising local resilience.

## 1. Overview
The HIDS agent utilizes a non-blocking background queue to forward detection and prevention events to a Central Socket Server via TCP. This enables aggregated fleet monitoring. 

**Critical Design Principle**: The network is inherently untrusted. The socket layer is purely a telemetry forwarder. All detection, Threat Memory tracking, Response Engine mitigation, and local JSON logging execute autonomously on the target machine regardless of network state.

## 2. The Socket Client (`hids/communication/socket_client.py`)
- **Background Worker**: Spawns a daemon thread `SocketClientWorker` on startup.
- **In-Memory Queue**: Intercepts events right after they are written to the local disk and places them in a `queue.Queue`. 
- **Non-Blocking**: If the TCP socket blocks, hangs, or drops, it only affects the background thread. The primary HIDS detection loop continues scanning at full speed (2Hz).
- **Offline Reliability**: If the central server is down, the client enters a sleep/retry loop (`HIDS_SOCKET_RECONNECT_INTERVAL`). Unsent events pool in the queue up to a maximum limit (`HIDS_SOCKET_QUEUE_LIMIT`), and will instantly drain to the server upon successful reconnection.

## 3. The Central Server (`socket_server.py`)
- **Standalone Daemon**: A lightweight `socketserver.ThreadingTCPServer` that can handle multiple inbound agent connections simultaneously.
- **Event Validation**: Parses inbound JSON lines and ensures critical schema fields exist (`agent_id`, `attack_name`, `action`).
- **Security Controls**: 
  - Restricts read buffers to 10KB to prevent memory exhaustion attacks.
  - Rejects malformed JSON explicitly without crashing.
  - Automatically appends the incoming IP address as `_server_receipt_ip` metadata to prevent spoofing.
- **Storage**: Validated events are appended to `central_events.jsonl` on the server machine.

## 4. Configuration
All socket parameters are centralized in `hids/config.py` and can be overridden via environment variables for easy deployment:

```python
HIDS_SOCKET_ENABLED = True
HIDS_SERVER_HOST = os.environ.get("HIDS_SERVER_HOST", "127.0.0.1")
HIDS_SERVER_PORT = int(os.environ.get("HIDS_SERVER_PORT", 9999))
HIDS_AGENT_ID = os.environ.get("HIDS_AGENT_ID", f"agent-{TARGET_USER}")
HIDS_SOCKET_RECONNECT_INTERVAL = 5  
HIDS_SOCKET_QUEUE_LIMIT = 1000      
```

## 5. Event Schema
The transmitted event mirrors the local `event_log.json` payload exactly, with the addition of the `agent_id`:

```json
{
  "agent_id": "agent-khushal",
  "timestamp": "2026-08-13 18:00:00",
  "attack_id": "mem_eater",
  "attack_name": "Parent-Child Memory Eater",
  "occurrence": 2,
  "severity": "HIGH",
  "mitre_id": "T1496",
  "mitre_tactic": "Impact",
  "action": "PREVENTED",
  "status": "Killed memory-abusing processes: [4501, 4502]",
  "details": ""
}
```

## 6. Systemd Integration
A new systemd template `deploy/systemd/central-server.service` has been provided to run the TCP server as a daemon. The existing local dashboard and API can be run alongside it, or disabled if central aggregation is strictly preferred.
