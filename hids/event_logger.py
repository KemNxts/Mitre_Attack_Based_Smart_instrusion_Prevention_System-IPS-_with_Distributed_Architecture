"""
=============================================================================
  Event Logger Module
  -------------------
  Appends every detection / prevention event to a persistent JSON-lines log.
  Also keeps an in-memory ring buffer so the dashboard can stream recent
  events without re-reading the file.
=============================================================================
"""

import json
import os
import threading
from datetime import datetime
from collections import deque

from hids.config import EVENT_LOG_FILE


class EventLogger:
    """Thread-safe event logger with file persistence + in-memory buffer."""

    MAX_BUFFER = 500  # keep last N events in memory

    def __init__(self, filepath: str = EVENT_LOG_FILE):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._buffer: deque = deque(maxlen=self.MAX_BUFFER)
        self._load_existing()

    def _load_existing(self):
        """Load previously logged events into the in-memory buffer."""
        if os.path.exists(self._filepath):
            try:
                with open(self._filepath, "r") as f:
                    events = json.load(f)
                    for evt in events[-self.MAX_BUFFER:]:
                        self._buffer.append(evt)
            except (json.JSONDecodeError, IOError):
                pass

    def _persist(self):
        """Write the full buffer to disk as a JSON array."""
        os.makedirs(os.path.dirname(self._filepath), exist_ok=True)
        with open(self._filepath, "w") as f:
            json.dump(list(self._buffer), f, indent=2, default=str)

    def log_event(self, attack_id: str, attack_name: str, occurrence: int,
                  severity: str, mitre_id: str, mitre_tactic: str,
                  action: str, status: str, details: str = ""):
        """
        Log a detection or prevention event.

        Parameters
        ----------
        attack_id    : unique attack identifier (e.g. "mem_eater")
        attack_name  : human name (e.g. "Parent-Child Memory Eater")
        occurrence   : how many times this attack has been seen (1, 2, ...)
        severity     : LOW / MEDIUM / HIGH / CRITICAL
        mitre_id     : MITRE ATT&CK technique (e.g. "T1496")
        mitre_tactic : MITRE tactic (e.g. "Impact")
        action       : DETECT_ONLY / PREVENTED / FAILED_PREVENTION
        status       : description of what happened
        details      : optional extra info
        """
        event = {
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_id":    attack_id,
            "attack_name":  attack_name,
            "occurrence":   occurrence,
            "severity":     severity,
            "mitre_id":     mitre_id,
            "mitre_tactic": mitre_tactic,
            "action":       action,
            "status":       status,
            "details":      details,
        }
        with self._lock:
            self._buffer.append(event)
            self._persist()
        return event

    def get_recent(self, n: int = 50) -> list:
        """Return the *n* most recent events (newest first)."""
        with self._lock:
            return list(self._buffer)[-n:][::-1]

    def get_all(self) -> list:
        """Return all buffered events (oldest first)."""
        with self._lock:
            return list(self._buffer)

    def clear(self):
        """Clear the event log."""
        with self._lock:
            self._buffer.clear()
            self._persist()
