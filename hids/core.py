"""
=============================================================================
  HIDS Core — Main Monitoring Loop
  ---------------------------------
  Ties together Detection Engine, Threat Memory, Response Engine, and
  Event Logger into one continuous monitoring daemon.
  
  This module is imported by the Streamlit dashboard (which runs it in a
  background thread) and can also be run standalone.
=============================================================================
"""

import time
import threading
import sys
from datetime import datetime

from hids.config import ATTACKS, SCAN_INTERVAL
from hids.detection_engine import DetectionEngine
from hids.threat_memory import ThreatMemory
from hids.response_engine import ResponseEngine
from hids.event_logger import EventLogger


class HIDSCore:
    """
    Main HIDS controller.
    
    Lifecycle:
        core = HIDSCore()
        core.start()      # starts scanning in a background thread
        ...
        core.stop()        # graceful shutdown
    """

    def __init__(self):
        self.detector  = DetectionEngine()
        self.memory    = ThreatMemory()
        self.responder = ResponseEngine()
        self.logger    = EventLogger()

        self._running  = False
        self._thread: threading.Thread | None = None

    # ── Thread management ───────────────────────────────────────────────
    def start(self):
        """Start the monitoring loop in a background daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._log_system("HIDS Core started — monitoring active")

    def stop(self):
        """Signal the monitoring loop to stop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        self._log_system("HIDS Core stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Main loop ───────────────────────────────────────────────────────
    def _run_loop(self):
        """Continuously scan, detect, decide, and respond."""
        while self._running:
            try:
                self._scan_cycle()
            except Exception as e:
                self._log_system(f"Scan cycle error: {e}")
            time.sleep(SCAN_INTERVAL)

    def _scan_cycle(self):
        """One full detection + response cycle."""
        detections = self.detector.scan()

        for det in detections:
            attack_id = det["attack_id"]
            attack_info = ATTACKS.get(attack_id, {})

            # Record in threat memory and get occurrence count
            occurrence = self.memory.record_occurrence(attack_id)
            should_prevent = (occurrence >= 2)

            if should_prevent:
                # ── AUTOMATIC PREVENTION ────────────────────────────────
                result = self.responder.prevent(attack_id, det)
                action = "PREVENTED" if result["success"] else "FAILED_PREVENTION"
                status = result["message"]
                ts = datetime.now().strftime("%H:%M:%S")
                prevention_msg = (
                    f"🛡️  {attack_info.get('name', attack_id)} prevented successfully at {ts}"
                    if result["success"]
                    else f"⚠️  Prevention FAILED for {attack_info.get('name', attack_id)} at {ts}"
                )
                print(f"\033[91m{prevention_msg}\033[0m")

                self.logger.log_event(
                    attack_id=attack_id,
                    attack_name=attack_info.get("name", attack_id),
                    occurrence=occurrence,
                    severity=attack_info.get("severity", "UNKNOWN"),
                    mitre_id=attack_info.get("mitre_id", ""),
                    mitre_tactic=attack_info.get("mitre_tactic", ""),
                    action=action,
                    status=status,
                    details=det.get("details", ""),
                )
            else:
                # ── FIRST OCCURRENCE — DETECT + LOG ONLY ────────────────
                print(
                    f"\033[93m⚡ DETECTED (1st time): {attack_info.get('name', attack_id)}"
                    f" — logging only, will prevent on next occurrence\033[0m"
                )
                self.logger.log_event(
                    attack_id=attack_id,
                    attack_name=attack_info.get("name", attack_id),
                    occurrence=occurrence,
                    severity=attack_info.get("severity", "UNKNOWN"),
                    mitre_id=attack_info.get("mitre_id", ""),
                    mitre_tactic=attack_info.get("mitre_tactic", ""),
                    action="DETECT_ONLY",
                    status="First occurrence — logged for threat memory",
                    details=det.get("details", ""),
                )

    def _log_system(self, message: str):
        """Log a system-level message (not attack-related)."""
        print(f"[HIDS] {datetime.now().strftime('%H:%M:%S')} — {message}")

    # ── Dashboard helpers ───────────────────────────────────────────────
    def get_recent_events(self, n: int = 50) -> list:
        return self.logger.get_recent(n)

    def get_all_events(self) -> list:
        return self.logger.get_all()

    def get_threat_memory(self) -> dict:
        return self.memory.get_all()

    def get_stats(self) -> dict:
        """Return summary statistics for the dashboard."""
        events = self.logger.get_all()
        total = len(events)
        detections = sum(1 for e in events if e["action"] == "DETECT_ONLY")
        preventions = sum(1 for e in events if e["action"] == "PREVENTED")
        failed = sum(1 for e in events if e["action"] == "FAILED_PREVENTION")

        # Count by severity
        severity_counts = {}
        for e in events:
            sev = e.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Count by attack type
        attack_counts = {}
        for e in events:
            aid = e.get("attack_id", "unknown")
            attack_counts[aid] = attack_counts.get(aid, 0) + 1

        return {
            "total_events": total,
            "detections_only": detections,
            "preventions": preventions,
            "failed_preventions": failed,
            "severity_counts": severity_counts,
            "attack_counts": attack_counts,
            "memory": self.memory.get_all(),
        }


# ── Standalone runner ───────────────────────────────────────────────────────
def main():
    """Run HIDS as a standalone daemon (no dashboard)."""
    print("=" * 60)
    print("  HIDS — Host-Based Intrusion Detection & Prevention")
    print("  Running in standalone mode (no dashboard)")
    print("=" * 60)

    core = HIDSCore()
    core.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[HIDS] Shutting down...")
        core.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
