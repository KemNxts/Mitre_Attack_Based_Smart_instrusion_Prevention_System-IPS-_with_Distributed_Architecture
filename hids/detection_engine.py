"""
=============================================================================
  Detection Engine
  ----------------
  Continuously scans the host for the 5 defined attack patterns using
  psutil (process monitoring) and filesystem checks.
  
  Each detector returns a dict with detection details or None.
=============================================================================
"""

import os
import time
import subprocess
import threading
from datetime import datetime, timedelta
from collections import defaultdict

import psutil

from hids.config import (
    ATTACKS,
    MEM_EATER_SCRIPT,
    DISCOVERY_COMMANDS, DISCOVERY_THRESHOLD, DISCOVERY_WINDOW,
    STAGING_WATCH_DIRS, STAGING_THRESHOLD, STAGING_WINDOW, STAGING_SUSPICIOUS_EXT,
    CRON_PAYLOAD_MARKER,
    SYSTEMD_SERVICE_NAME, SYSTEMD_USER_SERVICE_DIR, SYSTEMD_SYSTEM_SERVICE_DIR,
)


class DetectionEngine:
    """
    Host-based detection engine.
    Runs each detector and yields attack dicts when threats are found.
    """

    def __init__(self):
        # ── Discovery burst tracking ──
        # Maps parent PID → list of (timestamp, command_name)
        self._recon_history: dict[int, list] = defaultdict(list)
        self._recon_lock = threading.Lock()

        # ── Staging tracking ──
        # Snapshot of files in watched dirs to detect rapid creation
        self._staging_snapshots: dict[str, set] = {}
        self._staging_new_files: dict[str, list] = defaultdict(list)  # dir → [(ts, filepath)]
        self._staging_lock = threading.Lock()
        self._init_staging_snapshots()

        # Track which attacks are currently active to avoid duplicate alerts
        # Cleared when the attack is no longer detected
        self._active_alerts: set = set()
        self._alert_lock = threading.Lock()

        # ── Cooldown tracking ──
        # After an alert, don't re-alert for the same attack for N seconds
        self._cooldowns: dict[str, float] = {}
        self.COOLDOWN_SECONDS = 30

    # ── Staging snapshot init ───────────────────────────────────────────
    def _init_staging_snapshots(self):
        """Take an initial snapshot of files in staging-watched directories."""
        for d in STAGING_WATCH_DIRS:
            if os.path.isdir(d):
                try:
                    self._staging_snapshots[d] = set(os.listdir(d))
                except PermissionError:
                    self._staging_snapshots[d] = set()

    # ── Cooldown helper ─────────────────────────────────────────────────
    def _is_cooled_down(self, attack_id: str) -> bool:
        """Return True if enough time has passed since the last alert."""
        last = self._cooldowns.get(attack_id, 0)
        return (time.time() - last) >= self.COOLDOWN_SECONDS

    def _set_cooldown(self, attack_id: str):
        self._cooldowns[attack_id] = time.time()

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 1 — Parent-Child Memory Eater
    # ════════════════════════════════════════════════════════════════════
    def detect_mem_eater(self) -> dict | None:
        """
        Look for processes whose command line contains the mem_eater script.
        Alert if found with child processes.
        """
        attack_id = "mem_eater"
        if not self._is_cooled_down(attack_id):
            return None

        found_pids = []
        child_count = 0
        try:
            for proc in psutil.process_iter(["pid", "cmdline", "name"]):
                try:
                    cmdline = " ".join(proc.info["cmdline"] or [])
                    if MEM_EATER_SCRIPT in cmdline:
                        found_pids.append(proc.pid)
                        children = proc.children(recursive=True)
                        child_count += len(children)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            return None

        if found_pids:
            self._set_cooldown(attack_id)
            return {
                "attack_id": attack_id,
                "pids": found_pids,
                "child_count": child_count,
                "details": f"mem_eater.py running (PIDs: {found_pids}, children: {child_count})",
            }
        return None

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 2 — Cron Persistence
    # ════════════════════════════════════════════════════════════════════
    def detect_cron_persistence(self) -> dict | None:
        """
        Check crontab for entries containing persist_payload.sh.
        """
        attack_id = "cron_persist"
        if not self._is_cooled_down(attack_id):
            return None

        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=5
            )
            crontab_content = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        if CRON_PAYLOAD_MARKER in crontab_content:
            # Extract the offending lines
            bad_lines = [
                line.strip() for line in crontab_content.splitlines()
                if CRON_PAYLOAD_MARKER in line and not line.strip().startswith("#")
            ]
            self._set_cooldown(attack_id)
            return {
                "attack_id": attack_id,
                "cron_lines": bad_lines,
                "full_crontab": crontab_content,
                "details": f"Cron persistence detected: {bad_lines}",
            }
        return None

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 3 — Systemd User Service Persistence
    # ════════════════════════════════════════════════════════════════════
    def detect_systemd_persistence(self) -> dict | None:
        """
        Check for demo-persist.service in user or system systemd dirs,
        and whether it is enabled/active.
        """
        attack_id = "systemd_persist"
        if not self._is_cooled_down(attack_id):
            return None

        service_found = False
        service_path = None
        is_active = False

        # Check user service directory
        user_path = os.path.join(SYSTEMD_USER_SERVICE_DIR, SYSTEMD_SERVICE_NAME)
        system_path = os.path.join(SYSTEMD_SYSTEM_SERVICE_DIR, SYSTEMD_SERVICE_NAME)

        if os.path.exists(user_path):
            service_found = True
            service_path = user_path
        elif os.path.exists(system_path):
            service_found = True
            service_path = system_path

        if not service_found:
            # Also check if systemctl reports it
            try:
                result = subprocess.run(
                    ["systemctl", "--user", "is-active", SYSTEMD_SERVICE_NAME],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip() == "active":
                    service_found = True
                    is_active = True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        if not service_found:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", SYSTEMD_SERVICE_NAME],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip() == "active":
                    service_found = True
                    is_active = True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        if service_found:
            self._set_cooldown(attack_id)
            return {
                "attack_id": attack_id,
                "service_path": service_path,
                "is_active": is_active,
                "details": f"Systemd persistence: {SYSTEMD_SERVICE_NAME} found"
                           + (f" at {service_path}" if service_path else "")
                           + (" [ACTIVE]" if is_active else ""),
            }
        return None

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 4 — Discovery Burst
    # ════════════════════════════════════════════════════════════════════
    def detect_discovery_burst(self) -> dict | None:
        """
        Watch for rapid execution of reconnaissance commands.
        Uses process listing to find recon tools and tracks them by
        parent PID within a sliding time window.
        """
        attack_id = "discovery_burst"
        if not self._is_cooled_down(attack_id):
            return None

        now = datetime.now()
        window_start = now - timedelta(seconds=DISCOVERY_WINDOW)

        # Scan running processes for recon commands
        with self._recon_lock:
            for proc in psutil.process_iter(["pid", "ppid", "name", "create_time"]):
                try:
                    pname = proc.info["name"]
                    if pname in DISCOVERY_COMMANDS:
                        ppid = proc.info["ppid"]
                        ts = datetime.fromtimestamp(proc.info["create_time"])
                        # Only track recent ones
                        if ts >= window_start:
                            self._recon_history[ppid].append((ts, pname))
                except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                    continue

            # Prune old entries and check for bursts
            alert_ppid = None
            alert_cmds = []
            for ppid, entries in list(self._recon_history.items()):
                # Remove stale entries
                entries[:] = [(ts, cmd) for ts, cmd in entries if ts >= window_start]
                if not entries:
                    del self._recon_history[ppid]
                    continue
                # Check distinct commands
                unique_cmds = set(cmd for _, cmd in entries)
                if len(unique_cmds) >= DISCOVERY_THRESHOLD:
                    alert_ppid = ppid
                    alert_cmds = list(unique_cmds)
                    # Clear after alerting to avoid duplicates
                    del self._recon_history[ppid]
                    break

        if alert_ppid:
            self._set_cooldown(attack_id)
            return {
                "attack_id": attack_id,
                "parent_pid": alert_ppid,
                "commands": alert_cmds,
                "details": f"Discovery burst from PPID {alert_ppid}: {', '.join(alert_cmds)}",
            }
        return None

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 5 — Staging / Collection
    # ════════════════════════════════════════════════════════════════════
    def detect_staging(self) -> dict | None:
        """
        Monitor watched directories for rapid creation of new files,
        especially with suspicious extensions.
        """
        attack_id = "staging_collection"
        if not self._is_cooled_down(attack_id):
            return None

        now = time.time()
        window_start = now - STAGING_WINDOW

        with self._staging_lock:
            for watched_dir in STAGING_WATCH_DIRS:
                if not os.path.isdir(watched_dir):
                    continue
                try:
                    current_files = set(os.listdir(watched_dir))
                except PermissionError:
                    continue

                prev_files = self._staging_snapshots.get(watched_dir, set())
                new_files = current_files - prev_files

                # Filter for suspicious files
                suspicious = []
                for fname in new_files:
                    fpath = os.path.join(watched_dir, fname)
                    _, ext = os.path.splitext(fname)
                    if ext.lower() in STAGING_SUSPICIOUS_EXT:
                        suspicious.append(fpath)
                    elif os.path.isfile(fpath):
                        # Also track non-extension files that appeared rapidly
                        try:
                            ctime = os.path.getctime(fpath)
                            if ctime >= window_start:
                                suspicious.append(fpath)
                        except OSError:
                            pass

                # Record new files with timestamps
                for fpath in suspicious:
                    self._staging_new_files[watched_dir].append((now, fpath))

                # Prune old entries
                self._staging_new_files[watched_dir] = [
                    (ts, fp) for ts, fp in self._staging_new_files[watched_dir]
                    if ts >= window_start
                ]

                # Update snapshot
                self._staging_snapshots[watched_dir] = current_files

                # Check threshold
                recent = self._staging_new_files[watched_dir]
                if len(recent) >= STAGING_THRESHOLD:
                    staged_files = [fp for _, fp in recent]
                    # Clear after alerting
                    self._staging_new_files[watched_dir] = []
                    self._set_cooldown(attack_id)
                    return {
                        "attack_id": attack_id,
                        "directory": watched_dir,
                        "staged_files": staged_files,
                        "count": len(staged_files),
                        "details": f"Staging in {watched_dir}: {len(staged_files)} suspicious files",
                    }
        return None

    # ════════════════════════════════════════════════════════════════════
    #  Run All Detectors
    # ════════════════════════════════════════════════════════════════════
    def scan(self) -> list[dict]:
        """
        Run all detectors and return a list of triggered alerts.
        Each alert is a dict with at least 'attack_id' and 'details'.
        """
        results = []
        detectors = [
            self.detect_mem_eater,
            self.detect_cron_persistence,
            self.detect_systemd_persistence,
            self.detect_discovery_burst,
            self.detect_staging,
        ]
        for detector in detectors:
            try:
                result = detector()
                if result:
                    results.append(result)
            except Exception as e:
                # Never let one detector crash the whole engine
                pass
        return results
