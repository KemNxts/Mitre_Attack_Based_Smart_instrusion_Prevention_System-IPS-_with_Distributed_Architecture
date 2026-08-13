#!/usr/bin/env python3
"""
=============================================================================
  Phase 1 — Behavioral Detection Runner
  ──────────────────────────────────────
  Standalone script to learn baseline, then monitor for anomalies.

  Usage:
      # Full workflow: learn for 60s then monitor
      python3 run_behavioral.py

      # Custom learning duration
      python3 run_behavioral.py --learn 120

      # Skip learning (use existing baseline)
      python3 run_behavioral.py --skip-learning

      # Reset baseline and relearn
      python3 run_behavioral.py --reset --learn 90

      # Monitor only (heuristic mode, no baseline needed)
      python3 run_behavioral.py --heuristic
=============================================================================
"""

import sys
import os
import time
import argparse

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from hids.behavioral.behavioral_engine import BehavioralEngine
from hids.behavioral.baseline import BaselineBuilder, DEFAULT_BASELINE_PATH


def print_banner(mode: str):
    print("\n" + "═" * 65)
    print("  🧠 HIDS Phase 1 — Behavioral Anomaly Detection")
    print(f"  Mode: {mode}")
    print("  No filename matching — pure behavioral analysis")
    print("═" * 65 + "\n")


def run_learning_then_monitor(engine: BehavioralEngine, learn_duration: int):
    """Learn baseline, then automatically switch to monitoring."""
    print_banner(f"LEARNING ({learn_duration}s) → MONITORING")

    # Start learning (auto-transitions to monitoring when done)
    engine.start_learning(duration=learn_duration)

    # Wait for learning to finish
    while engine.mode == "LEARNING":
        time.sleep(1)

    # Now monitor continuously
    print("\n\033[92m[Phase 1] Now in MONITORING mode — watching for anomalies...\033[0m")
    print("\033[92m[Phase 1] Press Ctrl+C to stop\033[0m\n")

    monitor_loop(engine)


def run_skip_learning(engine: BehavioralEngine):
    """Skip learning, use existing baseline."""
    print_banner("MONITORING (existing baseline)")

    if not os.path.exists(DEFAULT_BASELINE_PATH):
        print("\033[93m[WARNING] No baseline found. Running with heuristic scoring.\033[0m")
        print("\033[93m         Run with --learn first for better accuracy.\033[0m\n")

    engine.start_monitoring()
    monitor_loop(engine)


def run_heuristic(engine: BehavioralEngine):
    """Pure heuristic mode — no baseline needed."""
    print_banner("HEURISTIC ONLY (no baseline)")

    # Remove baseline so scorer uses heuristics
    engine._baseline = BaselineBuilder()
    engine.start_monitoring()
    monitor_loop(engine)


def monitor_loop(engine: BehavioralEngine):
    """Continuous monitoring with console output."""
    from hids.config import SCAN_INTERVAL

    scan_count = 0
    total_alerts = 0

    try:
        while True:
            alerts = engine.scan()
            scan_count += 1

            if alerts:
                for alert_dict in alerts:
                    total_alerts += 1
                    severity = alert_dict["severity"]
                    color = {
                        "LOW": "\033[94m",       # blue
                        "MEDIUM": "\033[93m",     # yellow
                        "HIGH": "\033[91m",       # red
                        "CRITICAL": "\033[95m",   # magenta
                    }.get(severity, "\033[0m")

                    print(f"\n{color}{'━' * 65}")
                    print(f"  🚨 BEHAVIORAL ANOMALY DETECTED  [{severity}]")
                    print(f"  Score: {alert_dict['score']:.1f}")
                    print(f"  PID: {alert_dict['pid']}")
                    print(f"  Category: {alert_dict['attack_name']}")
                    print(f"  MITRE: {alert_dict['mitre_id']} ({alert_dict['mitre_tactic']})")
                    print(f"  Details: {alert_dict['details']}")

                    # Show top contributing features
                    features = alert_dict.get("features", [])
                    if features:
                        print(f"\n  Contributing factors:")
                        top_features = sorted(
                            features,
                            key=lambda f: f.get("contribution", 0),
                            reverse=True
                        )[:5]
                        for f in top_features:
                            print(
                                f"    • {f['feature']:35s} "
                                f"value={str(f.get('value', ''))[:15]:>15s}  "
                                f"contribution={f.get('contribution', 0):+.2f}"
                            )
                    print(f"{'━' * 65}\033[0m")
            else:
                # Periodic status (every 10 scans)
                if scan_count % 10 == 0:
                    status = engine.get_status()
                    ts = time.strftime("%H:%M:%S")
                    print(
                        f"\033[90m[{ts}] scan #{scan_count} | "
                        f"mode={status['mode']} | "
                        f"total_alerts={total_alerts}\033[0m"
                    )

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n\033[96m[Phase 1] Stopped. Total scans: {scan_count}, Total alerts: {total_alerts}\033[0m")
        engine.stop()
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="HIDS Phase 1 — Behavioral Anomaly Detection",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--learn", type=int, default=60,
        help="Baseline learning duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--skip-learning", action="store_true",
        help="Skip learning, use existing baseline file"
    )
    parser.add_argument(
        "--heuristic", action="store_true",
        help="Run in heuristic-only mode (no baseline)"
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Delete existing baseline before starting"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Process collection interval in seconds (default: 2.0)"
    )

    args = parser.parse_args()

    # Reset if requested
    if args.reset and os.path.exists(DEFAULT_BASELINE_PATH):
        os.remove(DEFAULT_BASELINE_PATH)
        print("🗑️  Deleted existing baseline")

    engine = BehavioralEngine(collect_interval=args.interval)

    if args.heuristic:
        run_heuristic(engine)
    elif args.skip_learning:
        run_skip_learning(engine)
    else:
        run_learning_then_monitor(engine, args.learn)


if __name__ == "__main__":
    main()
