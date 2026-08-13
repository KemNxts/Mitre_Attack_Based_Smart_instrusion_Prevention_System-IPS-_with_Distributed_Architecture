"""
=============================================================================
  Test Attack Simulator
  ---------------------
  Simulates the 5 real attack patterns for testing the HIDS.
  Run individual attacks to verify detection + prevention.
  
  ⚠️  This script creates REAL processes, cron entries, systemd services,
      and files. Only run on a test/lab machine.
=============================================================================
"""

import os
import sys
import time
import subprocess
import tempfile
import argparse
import multiprocessing

from hids.config import TARGET_HOME_DIR, SUSPICIOUS_MEMORY_SCRIPTS

def simulate_mem_eater():
    """
    Simulate Attack 1: Parent-Child Memory Eater (dump.py).
    Creates the dump.py script and runs it with child processes.
    """
    print("🔴 [Attack 1] Simulating Memory Abuse...")

    script_name = SUSPICIOUS_MEMORY_SCRIPTS[0] if SUSPICIOUS_MEMORY_SCRIPTS else "dump.py"
    script_path = os.path.join(TARGET_HOME_DIR, "bin", script_name)
    os.makedirs(os.path.dirname(script_path), exist_ok=True)

    # Create the memory eater script
    script_content = '''#!/usr/bin/env python3
"""dump.py — spawns child processes that consume memory."""
import os, time, multiprocessing

def eat_memory():
    """Child process: allocate memory in a loop."""
    data = []
    for i in range(50):
        data.append(b"X" * (1024 * 100))  # 100KB chunks
        time.sleep(0.5)
    time.sleep(300)

if __name__ == "__main__":
    children = []
    for i in range(3):
        p = multiprocessing.Process(target=eat_memory)
        p.start()
        children.append(p)
        print(f"Spawned child PID {p.pid}")

    print(f"Parent PID {os.getpid()} with {len(children)} children")
    try:
        for p in children:
            p.join()
    except KeyboardInterrupt:
        for p in children:
            p.terminate()
'''
    with open(script_path, "w") as f:
        f.write(script_content)
    os.chmod(script_path, 0o755)

    # Run it
    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    print(f"  ✅ dump.py started with PID {proc.pid}")
    print(f"  📍 Script at: {script_path}")
    print(f"  ⏳ HIDS should detect this within a few seconds...")
    return proc


def simulate_cron_persistence():
    """
    Simulate Attack 2: Cron Persistence.
    Adds a cron entry with persist_payload.sh.
    """
    print("🔴 [Attack 2] Simulating Cron Persistence...")

    # Get current crontab
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current = result.stdout if result.returncode == 0 else ""
    except FileNotFoundError:
        current = ""

    # Add malicious entry if not already there
    marker = "persist_payload.sh"
    if marker not in current:
        new_entry = f"*/5 * * * * /tmp/persist_payload.sh  # backdoor persistence\n"
        new_crontab = current + new_entry
        proc = subprocess.run(
            ["crontab", "-"],
            input=new_crontab, capture_output=True, text=True
        )
        if proc.returncode == 0:
            print(f"  ✅ Malicious cron entry added: {new_entry.strip()}")
        else:
            print(f"  ❌ Failed to add cron entry: {proc.stderr}")
    else:
        print(f"  ℹ️  Cron entry already exists")

    print(f"  ⏳ HIDS should detect this within a few seconds...")


def simulate_systemd_persistence():
    """
    Simulate Attack 3: Systemd User Service Persistence.
    Creates a demo-persist.service in user systemd directory.
    """
    print("🔴 [Attack 3] Simulating Systemd User Service Persistence...")

    service_dir = os.path.join(TARGET_HOME_DIR, ".config/systemd/user")
    os.makedirs(service_dir, exist_ok=True)

    service_content = """[Unit]
Description=Demo Persistence Service (HIDS Test)
After=default.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do echo "persistence active" >> /tmp/persist.log; sleep 60; done'
Restart=always

[Install]
WantedBy=default.target
"""
    service_path = os.path.join(service_dir, "demo-persist.service")
    with open(service_path, "w") as f:
        f.write(service_content)

    # Reload and enable
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "--user", "enable", "demo-persist.service"], capture_output=True)
    subprocess.run(["systemctl", "--user", "start", "demo-persist.service"], capture_output=True)

    print(f"  ✅ Service created at: {service_path}")
    print(f"  ✅ Service enabled and started")
    print(f"  ⏳ HIDS should detect this within a few seconds...")


def simulate_discovery_burst():
    """
    Simulate Attack 4: Discovery Burst.
    Rapidly execute multiple reconnaissance commands.
    """
    print("🔴 [Attack 4] Simulating Discovery Burst...")

    recon_commands = [
        ["whoami"],
        ["id"],
        ["uname", "-a"],
        ["hostname"],
        ["ps", "aux"],
        ["netstat", "-tlnp"],
        ["df", "-h"],
        ["env"],
    ]

    for cmd in recon_commands:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
            print(f"  🔍 Executed: {' '.join(cmd)}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.3)  # rapid but not instant

    print(f"  ⏳ HIDS should detect the burst within a few seconds...")


def simulate_staging():
    """
    Simulate Attack 5: Staging / Collection.
    Rapidly create suspicious files in /tmp.
    """
    print("🔴 [Attack 5] Simulating Staging / Collection...")

    staging_dir = "/tmp"
    files_created = []

    for i in range(8):
        fname = f"staged_data_{i}.tar.gz"
        fpath = os.path.join(staging_dir, fname)
        with open(fpath, "wb") as f:
            f.write(os.urandom(1024 * 10))  # 10KB of random data
        files_created.append(fpath)
        print(f"  📄 Created: {fpath}")
        time.sleep(0.5)

    print(f"  ✅ Created {len(files_created)} staged files")
    print(f"  ⏳ HIDS should detect this within a few seconds...")


# ═══════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="HIDS Test Attack Simulator",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "attack",
        choices=["mem_eater", "cron", "systemd", "discovery", "staging", "all"],
        help=(
            "Attack to simulate:\n"
            "  mem_eater  — Parent-Child Memory Eater\n"
            "  cron       — Cron Persistence\n"
            "  systemd    — Systemd User Service Persistence\n"
            "  discovery  — Discovery Burst (recon commands)\n"
            "  staging    — Staging / Collection\n"
            "  all        — Run all attacks sequentially"
        ),
    )
    parser.add_argument(
        "--delay", type=int, default=5,
        help="Seconds to wait between attacks when running 'all' (default: 5)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  HIDS Test Attack Simulator")
    print("  ⚠️  Running real attack simulations on this host")
    print("=" * 60)
    print()

    attacks = {
        "mem_eater": simulate_mem_eater,
        "cron": simulate_cron_persistence,
        "systemd": simulate_systemd_persistence,
        "discovery": simulate_discovery_burst,
        "staging": simulate_staging,
    }

    if args.attack == "all":
        for name, func in attacks.items():
            func()
            print(f"\n  ⏳ Waiting {args.delay}s before next attack...\n")
            time.sleep(args.delay)
    else:
        attacks[args.attack]()

    print("\n" + "=" * 60)
    print("  ✅ Attack simulation complete")
    print("  📊 Check the HIDS dashboard to see detections")
    print("=" * 60)


if __name__ == "__main__":
    main()
