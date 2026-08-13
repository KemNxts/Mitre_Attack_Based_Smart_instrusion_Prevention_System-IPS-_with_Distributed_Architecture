#!/usr/bin/env python3
"""
=============================================================================
  HIDS Runner
  -----------
  Single entry point to start the HIDS system.
  
  Usage:
    python run_hids.py                  # Start dashboard + monitoring
    python run_hids.py --headless       # Monitoring only (no dashboard)
    python run_hids.py --reset          # Reset threat memory and start
=============================================================================
"""

import sys
import os
import argparse
import subprocess

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def main():
    parser = argparse.ArgumentParser(description="HIDS — Host-Based Intrusion Detection & Prevention")
    parser.add_argument("--headless", action="store_true", help="Run monitoring only (no web dashboard)")
    parser.add_argument("--reset", action="store_true", help="Reset threat memory before starting")
    parser.add_argument("--port", type=int, default=8501, help="Dashboard port (default: 8501)")
    args = parser.parse_args()

    if args.reset:
        from hids.threat_memory import ThreatMemory
        from hids.event_logger import EventLogger
        ThreatMemory().reset()
        EventLogger().clear()
        print("✅ Threat memory and event logs cleared.")

    if args.headless:
        # Run monitoring without dashboard
        from hids.core import main as hids_main
        hids_main()
    else:
        # Launch Streamlit dashboard (which starts monitoring internally)
        dashboard_path = os.path.join(PROJECT_ROOT, "hids", "dashboard.py")
        print("=" * 60)
        print("  🛡️  HIDS — Starting Live Dashboard")
        print(f"  📊 Dashboard: http://localhost:{args.port}")
        print("  ⌨️  Press Ctrl+C to stop")
        print("=" * 60)

        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            dashboard_path,
            "--server.port", str(args.port),
            "--server.headless", "true",
            "--theme.base", "dark",
            "--theme.primaryColor", "#58a6ff",
            "--theme.backgroundColor", "#0d1117",
            "--theme.secondaryBackgroundColor", "#161b22",
            "--theme.textColor", "#e6edf3",
        ])


if __name__ == "__main__":
    main()
