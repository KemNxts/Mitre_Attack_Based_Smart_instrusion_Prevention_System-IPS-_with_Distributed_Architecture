"""
=============================================================================
  Threat Memory Module
  --------------------
  Tracks how many times each attack type has been seen.
  
  Policy:
    • 1st occurrence  →  DETECT + LOG only  (learn the threat)
    • 2nd occurrence+  →  DETECT + AUTO-PREVENT  (adaptive response)
  
  Persistence: JSON file on disk, survives restarts.
=============================================================================
"""

import json
import os
import threading
from datetime import datetime

from hids.config import THREAT_MEMORY_FILE


class ThreatMemory:
    """Thread-safe persistent memory of previously seen attacks."""

    def __init__(self, filepath: str = THREAT_MEMORY_FILE):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._memory: dict = self._load()

    # ── Persistence ─────────────────────────────────────────────────────
    def _load(self) -> dict:
        """Load threat memory from disk."""
        if os.path.exists(self._filepath):
            try:
                with open(self._filepath, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save(self):
        """Persist current memory to disk."""
        os.makedirs(os.path.dirname(self._filepath), exist_ok=True)
        with open(self._filepath, "w") as f:
            json.dump(self._memory, f, indent=2, default=str)

    # ── Public API ──────────────────────────────────────────────────────
    def record_occurrence(self, attack_id: str) -> int:
        """
        Record that we just detected *attack_id*.
        Returns the new count (1 = first time, 2+ = prevention eligible).
        """
        with self._lock:
            entry = self._memory.get(attack_id, {
                "count": 0,
                "first_seen": None,
                "last_seen": None,
            })
            entry["count"] += 1
            now = datetime.now().isoformat()
            if entry["first_seen"] is None:
                entry["first_seen"] = now
            entry["last_seen"] = now
            self._memory[attack_id] = entry
            self._save()
            return entry["count"]

    def get_count(self, attack_id: str) -> int:
        """Return how many times *attack_id* has been seen (0 if never)."""
        with self._lock:
            return self._memory.get(attack_id, {}).get("count", 0)

    def should_prevent(self, attack_id: str) -> bool:
        """Return True if this attack has been seen before (count >= 2)."""
        return self.get_count(attack_id) >= 2

    def get_all(self) -> dict:
        """Return a copy of the full memory dict."""
        with self._lock:
            return dict(self._memory)

    def reset(self, attack_id: str | None = None):
        """Reset memory for one attack or all attacks."""
        with self._lock:
            if attack_id:
                self._memory.pop(attack_id, None)
            else:
                self._memory.clear()
            self._save()
