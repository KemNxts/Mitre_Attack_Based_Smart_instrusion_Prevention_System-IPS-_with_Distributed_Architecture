#!/usr/bin/env python3
"""
=============================================================================
  Hybrid HIDS Runner
  ------------------
  Runs the Hybrid Detection Engine with Threat Memory and Response Engine.

  Usage:
      python3 run_hybrid.py                 # normal monitoring
      python3 run_hybrid.py --reset         # clear memory + logs, then monitor
      python3 run_hybrid.py --test          # dry run (no prevention, just alerts)
=============================================================================
"""

import sys
import os
import time
import argparse
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from hids.behavioral.hybrid_engine import HybridEngine
from hids.threat_memory import ThreatMemory
from hids.response_engine import ResponseEngine
from hids.event_logger import EventLogger
from hids.config import FAST_SCAN_INTERVAL, ATTACKS


def main():
    parser = argparse.ArgumentParser(description="Hybrid HIDS — Behavioral + Smart Rules")
    parser.add_argument("--reset", action="store_true", help="Reset memory and logs")
    parser.add_argument("--test", action="store_true", help="Dry run — detect only, no prevention")
    args = parser.parse_args()

    memory = ThreatMemory()
    responder = ResponseEngine()
    logger = EventLogger()

    if args.reset:
        memory.reset()
        logger.clear()
        print("✅ Memory and logs cleared\n")

    engine = HybridEngine(collect_interval=FAST_SCAN_INTERVAL)
    engine.start()

    # Wait for collector to gather first snapshot
    print("═" * 65)
    print("  🛡️  HYBRID HIDS — Behavioral + Smart Rules")
    print("  Waiting for first process snapshot...")
    print("═" * 65)
    time.sleep(7)  # first snapshot takes ~5s for 400+ processes

    print(f"\n\033[92m[HYBRID] Monitoring active — process scan every {FAST_SCAN_INTERVAL}s\033[0m")
    print(f"\033[92m[HYBRID] Press Ctrl+C to stop\033[0m\n")

    scan_count = 0
    total_alerts = 0

    # Attack info lookup for logger compatibility
    HYBRID_ATTACKS = {
        "memory_abuse": {
            "name": "Memory Abuse / Resource Hijacking",
            "mitre_id": "T1496", "mitre_tactic": "Impact", "severity": "HIGH",
        },
        "cron_persist": ATTACKS.get("cron_persist", {}),
        "systemd_persist": ATTACKS.get("systemd_persist", {}),
        "discovery_burst": ATTACKS.get("discovery_burst", {}),
        "staging_collection": ATTACKS.get("staging_collection", {}),
    }

    try:
        while True:
            alerts = engine.scan()
            scan_count += 1

            for alert_dict in alerts:
                total_alerts += 1
                attack_id = alert_dict["attack_id"]
                attack_name = alert_dict["attack_name"]
                severity = alert_dict["severity"]
                score = alert_dict["score"]
                reasons = alert_dict.get("reasons", [])

                # Record in threat memory
                occurrence = memory.record_occurrence(attack_id)
                should_prevent = (occurrence >= 2) and not args.test

                # Color by severity
                color = {
                    "LOW": "\033[94m", "MEDIUM": "\033[93m",
                    "HIGH": "\033[91m", "CRITICAL": "\033[95m",
                }.get(severity, "\033[0m")

                ts = datetime.now().strftime("%H:%M:%S")

                if should_prevent:
                    # AUTOMATIC PREVENTION
                    result = responder.prevent(attack_id, alert_dict)
                    action = "PREVENTED" if result["success"] else "FAILED_PREVENTION"
                    icon = "🛡️" if result["success"] else "⚠️"

                    print(f"\n{color}{'━' * 65}")
                    print(f"  {icon} {attack_name} — {'PREVENTED' if result['success'] else 'PREVENTION FAILED'}")
                    print(f"  Occurrence: #{occurrence}  |  Score: {score:.1f}  |  Severity: {severity}")
                    print(f"  Action: {result['message']}")
                    for r in reasons[:3]:
                        print(f"    → {r}")
                    print(f"  Time: {ts}")
                    print(f"{'━' * 65}\033[0m")

                    logger.log_event(
                        attack_id=attack_id, attack_name=attack_name,
                        occurrence=occurrence, severity=severity,
                        mitre_id=alert_dict.get("mitre_id", ""),
                        mitre_tactic=alert_dict.get("mitre_tactic", ""),
                        action=action, status=result["message"],
                        details=alert_dict.get("details", ""),
                    )
                else:
                    # DETECT + LOG
                    mode = "TEST MODE — " if args.test else ""
                    label = "Learning" if occurrence == 1 else f"#{occurrence}"
                    print(f"\n{color}{'━' * 65}")
                    print(f"  ⚡ {mode}DETECTED: {attack_name}")
                    print(f"  Occurrence: {label}  |  Score: {score:.1f}  |  Severity: {severity}")
                    for r in reasons[:3]:
                        print(f"    → {r}")
                    if occurrence == 1:
                        print(f"  📝 1st time — logged for threat memory. Will prevent on next.")
                    print(f"  Time: {ts}")
                    print(f"{'━' * 65}\033[0m")

                    logger.log_event(
                        attack_id=attack_id, attack_name=attack_name,
                        occurrence=occurrence, severity=severity,
                        mitre_id=alert_dict.get("mitre_id", ""),
                        mitre_tactic=alert_dict.get("mitre_tactic", ""),
                        action="DETECT_ONLY",
                        status=f"Occurrence #{occurrence} — logged for threat memory",
                        details=alert_dict.get("details", ""),
                    )

            # Periodic status
            if scan_count % int(10 / FAST_SCAN_INTERVAL) == 0 and not alerts:
                ts = time.strftime("%H:%M:%S")
                print(f"\033[90m[{ts}] scan #{scan_count} | alerts_total={total_alerts} | clean\033[0m")

            time.sleep(FAST_SCAN_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n\033[96m[HYBRID] Stopped. Scans: {scan_count} | Alerts: {total_alerts}\033[0m")
        engine.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
