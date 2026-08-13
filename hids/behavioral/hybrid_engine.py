"""
=============================================================================
  Hybrid Detection Engine
  -----------------------
  Combines behavioral features (process tree, memory, rarity) with smart
  practical rules to detect real attacks while suppressing false positives
  from Chrome, gnome-shell, and other normal desktop applications.

  Detection Strategy per Attack:
      1. Memory Abuse (dump.py)   → Python + high RSS + child tree
      2. Cron Persistence         → crontab entries running user scripts
      3. Systemd Persistence      → user service files from home dir
      4. Discovery Burst          → rapid recon commands from same parent
      5. Staging / Collection     → rapid file creation in /tmp or ~

  Output is compatible with ThreatMemory and ResponseEngine.
=============================================================================
"""

import os
import time
import subprocess
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

import psutil

from hids.config import (
    ATTACKS, FAST_SCAN_INTERVAL, SLOW_SCAN_INTERVAL,
    SUSPICIOUS_MEMORY_SCRIPTS, TARGET_HOME_DIR,
    KNOWN_SAFE_PROCESSES, SAFE_EXE_PREFIXES,
    MEM_ABUSE_RSS_THRESHOLD, MEM_ABUSE_CHILDREN_MIN,
    DISCOVERY_COMMANDS, DISCOVERY_BURST_MIN_CMDS, DISCOVERY_BURST_WINDOW,
    CRON_PAYLOAD_MARKER,
    SYSTEMD_SERVICE_NAME, SYSTEMD_USER_SERVICE_DIR, SYSTEMD_SYSTEM_SERVICE_DIR,
    STAGING_WATCH_DIRS, STAGING_MIN_FILES, STAGING_TIME_WINDOW,
    STAGING_SUSPICIOUS_EXT,
    MASQUERADE_NAMES, SHELL_RC_FILES, SHELL_RC_MARKERS,
)
from hids.behavioral.collector import DataCollector, ProcessRecord
from hids.behavioral.features import FeatureExtractor, FeatureVector


class HybridAlert:
    """One detection from the hybrid engine."""

    def __init__(self, attack_id: str, attack_name: str, severity: str,
                 mitre_id: str, mitre_tactic: str, score: float,
                 details: str, reasons: list[str],
                 pids: list[int] = None, extra: dict = None):
        self.attack_id = attack_id
        self.attack_name = attack_name
        self.severity = severity
        self.mitre_id = mitre_id
        self.mitre_tactic = mitre_tactic
        self.score = score
        self.details = details
        self.reasons = reasons          # human-readable reason list
        self.pids = pids or []
        self.extra = extra or {}        # attack-specific data for ResponseEngine

    def to_dict(self) -> dict:
        """Format compatible with ThreatMemory / ResponseEngine / EventLogger."""
        return {
            "attack_id":    self.attack_id,
            "attack_name":  self.attack_name,
            "severity":     self.severity,
            "mitre_id":     self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "score":        self.score,
            "details":      self.details,
            "reasons":      self.reasons,
            "pids":         self.pids,
            # Extra fields for ResponseEngine
            **self.extra,
        }

    def summary(self) -> str:
        return (
            f"[{self.severity}] {self.attack_name} (score={self.score:.1f}) — "
            + "; ".join(self.reasons[:3])
        )


class HybridEngine:
    """
    Combines behavioral feature analysis with smart contextual rules.
    Produces low false-positive, high true-positive alerts.
    """

    def __init__(self, collect_interval: float = 2.0):
        self._collector = DataCollector(interval=collect_interval)
        self._extractor = FeatureExtractor()

        # Cooldowns: don't re-alert same attack_id within window
        self._cooldowns: dict[str, float] = {}
        self.COOLDOWN_SECONDS = 30

        # Discovery burst tracking: ppid → [(timestamp, cmd_name)]
        self._recon_history: dict[int, list] = defaultdict(list)

        # Staging tracking: dir → set of known files
        self._staging_snapshots: dict[str, set] = {}
        self._staging_new_files: dict[str, list] = defaultdict(list)
        self._init_staging()

        self._running = False
        self._last_slow_scan = 0.0

    # ── Lifecycle ───────────────────────────────────────────────────────
    def start(self):
        if not self._collector.is_running:
            self._collector.start()
        self._running = True

    def stop(self):
        self._running = False
        self._collector.stop()

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Cooldown ────────────────────────────────────────────────────────
    def _check_cooldown(self, attack_id: str) -> bool:
        """True if we can alert (cooldown expired)."""
        last = self._cooldowns.get(attack_id, 0)
        return (time.time() - last) >= self.COOLDOWN_SECONDS

    def _set_cooldown(self, attack_id: str):
        self._cooldowns[attack_id] = time.time()

    # ── Staging init ────────────────────────────────────────────────────
    def _init_staging(self):
        for d in STAGING_WATCH_DIRS:
            if os.path.isdir(d):
                try:
                    self._staging_snapshots[d] = set(os.listdir(d))
                except PermissionError:
                    self._staging_snapshots[d] = set()

    # ════════════════════════════════════════════════════════════════════
    #  MAIN SCAN — called every cycle
    # ════════════════════════════════════════════════════════════════════
    def scan(self) -> list[dict]:
        """
        Run all hybrid detectors. Returns alert dicts compatible with
        ThreatMemory / ResponseEngine.
        """
        results = []

        # Wait for collector to have data
        snapshot = self._collector.latest_snapshot()
        if not snapshot:
            return []

        # Build lookup structures
        pid_map = {rec.pid: rec for rec in snapshot}

        # Extract behavioral features for enrichment
        vectors = self._extractor.extract(snapshot)
        fv_map = {fv.pid: fv for fv in vectors}

        # ── Fast Detectors (Process Behavior) ──
        detectors = [
            lambda: self._detect_memory_abuse(snapshot, pid_map, fv_map),
            lambda: self._detect_discovery_burst(snapshot, pid_map),
            lambda: self._detect_masquerading(snapshot),
        ]

        # ── Slow Detectors (Persistence & File I/O) ──
        now_ts = time.time()
        if (now_ts - self._last_slow_scan) >= SLOW_SCAN_INTERVAL:
            detectors.extend([
                lambda: self._detect_cron_persistence(),
                lambda: self._detect_systemd_persistence(),
                lambda: self._detect_staging(),
                lambda: self._detect_shell_rc_persistence(),
            ])
            self._last_slow_scan = now_ts

        for detector in detectors:
            try:
                alert = detector()
                if alert:
                    results.append(alert.to_dict())
            except Exception:
                pass  # never crash

        return results

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 1 — Memory Abuse / Resource Hijacking
    # ════════════════════════════════════════════════════════════════════
    def _detect_memory_abuse(self, snapshot: list[ProcessRecord],
                             pid_map: dict, fv_map: dict
                             ) -> Optional[HybridAlert]:
        """
        Detect memory-abusing Python processes.

        Behavioral signals:
            - Python/python3 process with high RSS
            - Multiple child processes also consuming memory
            - Script running from user's home/bin directory
            - Unusual parent-child tree depth

        Smart rule: specifically looks for dump.py or similar patterns
        but also catches ANY Python process exhibiting abuse behavior.
        """
        if not self._check_cooldown("memory_abuse"):
            return None

        # Find all Python processes
        python_procs = []
        for rec in snapshot:
            name = (rec.name or "").lower()
            if name in ("python", "python3", "python3.12", "python3.11",
                        "python3.10", "python3.9"):
                # Skip if it's a safe/known process
                if self._is_safe_process(rec):
                    continue
                python_procs.append(rec)

        if not python_procs:
            return None

        # Evaluate each Python process tree for abuse
        best_score = 0.0
        best_reasons = []
        best_pids = []
        best_rec = None

        for rec in python_procs:
            score = 0.0
            reasons = []
            cmdline = rec.cmdline or ""

            # ── Rule: script from user home/bin ─────────────────────
            # Skip our own HIDS processes
            if any(marker in cmdline for marker in
                   ["run_hids", "run_hybrid", "run_behavioral",
                    "streamlit", "dashboard.py", "test_attacks"]):
                continue

            if TARGET_HOME_DIR in cmdline and "/bin/" in cmdline:
                score += 8.0
                reasons.append(f"Script from user bin: {cmdline[:80]}")

            if any(script in cmdline for script in SUSPICIOUS_MEMORY_SCRIPTS):
                score += 10.0
                reasons.append("Suspicious memory script in command line")

            # ── Behavioral: high memory ─────────────────────────────
            rss_mb = (rec.rss_bytes or 0) / (1024 * 1024)
            if rss_mb > MEM_ABUSE_RSS_THRESHOLD:
                bonus = min((rss_mb - MEM_ABUSE_RSS_THRESHOLD) / 25.0, 10.0)
                score += bonus
                reasons.append(f"High RSS: {rss_mb:.0f} MB")

            # ── Behavioral: children also eating memory ─────────────
            children = []
            try:
                p = psutil.Process(rec.pid)
                children = p.children(recursive=True)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            child_mem_total = 0
            for child in children:
                try:
                    child_mem = child.memory_info().rss / (1024 * 1024)
                    child_mem_total += child_mem
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            if len(children) >= MEM_ABUSE_CHILDREN_MIN:
                score += 5.0 + len(children)
                reasons.append(
                    f"{len(children)} child processes "
                    f"(total child mem: {child_mem_total:.0f} MB)"
                )

            # ── Behavioral: unusual tree depth ──────────────────────
            fv = fv_map.get(rec.pid)
            if fv and (fv.tree_depth or 0) >= 4:
                score += 2.0
                reasons.append(f"Deep process tree: depth={fv.tree_depth}")

            # ── Behavioral: rare exe/parent-child ───────────────────
            if fv and (fv.exe_rarity or 0) > 0.3:
                score += 1.5
                reasons.append(f"Rare executable (rarity={fv.exe_rarity:.2f})")

            if score > best_score:
                best_score = score
                best_reasons = reasons
                best_rec = rec
                best_pids = [rec.pid] + [c.pid for c in children]

        if best_score < 8.0:
            return None

        # Classify severity
        severity = self._score_to_severity(best_score)

        self._set_cooldown("memory_abuse")
        return HybridAlert(
            attack_id="memory_abuse",
            attack_name="Memory Abuse / Resource Hijacking",
            severity=severity,
            mitre_id="T1496",
            mitre_tactic="Impact",
            score=best_score,
            details=f"Python process PID {best_rec.pid} abusing memory | "
                    + " | ".join(best_reasons),
            reasons=best_reasons,
            pids=best_pids,
            extra={"pids": best_pids},
        )

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 2 — Cron Persistence
    # ════════════════════════════════════════════════════════════════════
    def _detect_cron_persistence(self) -> Optional[HybridAlert]:
        """
        Smart rule: check crontab for suspicious entries.
        Behavioral signal: entries pointing to user home/bin scripts.
        """
        if not self._check_cooldown("cron_persist"):
            return None

        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=5
            )
            crontab = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        if not crontab:
            return None

        score = 0.0
        reasons = []
        bad_lines = []

        for line in crontab.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Rule: known payload marker
            if CRON_PAYLOAD_MARKER in line:
                score += 15.0
                reasons.append(f"Payload marker found: {CRON_PAYLOAD_MARKER}")
                bad_lines.append(line)

            # Behavioral: cron executing from user home/bin
            elif TARGET_HOME_DIR in line and "/bin/" in line:
                score += 8.0
                reasons.append(f"Cron runs user script: {line[:60]}")
                bad_lines.append(line)

            # Behavioral: cron running python/bash with suspicious args
            elif any(cmd in line for cmd in ["python", "bash", "sh", "curl", "wget"]):
                if "/tmp/" in line or TARGET_HOME_DIR in line:
                    score += 5.0
                    reasons.append(f"Cron runs interpreter with user path: {line[:60]}")
                    bad_lines.append(line)

        if score < 5.0:
            return None

        severity = self._score_to_severity(score)
        self._set_cooldown("cron_persist")

        return HybridAlert(
            attack_id="cron_persist",
            attack_name="Cron Persistence",
            severity=severity,
            mitre_id="T1053.003",
            mitre_tactic="Persistence",
            score=score,
            details=f"Suspicious cron entries detected | " + " | ".join(reasons),
            reasons=reasons,
            extra={"cron_lines": bad_lines, "full_crontab": crontab},
        )

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 3 — Systemd User Service Persistence
    # ════════════════════════════════════════════════════════════════════
    def _detect_systemd_persistence(self) -> Optional[HybridAlert]:
        """
        Smart rule: check for rogue user systemd services.
        Behavioral: services executing from user home directory.
        """
        if not self._check_cooldown("systemd_persist"):
            return None

        score = 0.0
        reasons = []
        service_path = None

        # Check for the known demo service
        for sdir in [SYSTEMD_USER_SERVICE_DIR, SYSTEMD_SYSTEM_SERVICE_DIR]:
            spath = os.path.join(sdir, SYSTEMD_SERVICE_NAME)
            if os.path.exists(spath):
                score += 15.0
                service_path = spath
                reasons.append(f"Known rogue service found: {spath}")
                # Read the service to check ExecStart
                try:
                    with open(spath) as f:
                        content = f.read()
                    if TARGET_HOME_DIR in content:
                        score += 5.0
                        reasons.append("Service ExecStart points to user home")
                except Exception:
                    pass

        # Behavioral: scan user service dir for ANY suspicious services
        if os.path.isdir(SYSTEMD_USER_SERVICE_DIR):
            for sfile in os.listdir(SYSTEMD_USER_SERVICE_DIR):
                if not sfile.endswith(".service"):
                    continue
                if sfile == SYSTEMD_SERVICE_NAME:
                    continue  # already counted
                spath = os.path.join(SYSTEMD_USER_SERVICE_DIR, sfile)
                try:
                    with open(spath) as f:
                        content = f.read()
                    if TARGET_HOME_DIR in content and ("/bin/" in content or "/tmp/" in content):
                        score += 8.0
                        reasons.append(f"Suspicious user service: {sfile}")
                        if service_path is None:
                            service_path = spath
                except Exception:
                    pass

        # Check if service is active
        try:
            result = subprocess.run(
                ["systemctl", "--user", "is-active", SYSTEMD_SERVICE_NAME],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip() == "active":
                score += 5.0
                reasons.append(f"{SYSTEMD_SERVICE_NAME} is ACTIVE")
        except Exception:
            pass

        if score < 8.0:
            return None

        severity = self._score_to_severity(score)
        self._set_cooldown("systemd_persist")

        return HybridAlert(
            attack_id="systemd_persist",
            attack_name="Systemd User Service Persistence",
            severity=severity,
            mitre_id="T1543.002",
            mitre_tactic="Persistence",
            score=score,
            details=f"Rogue systemd service detected | " + " | ".join(reasons),
            reasons=reasons,
            extra={"service_path": service_path},
        )

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 4 — Discovery Burst
    # ════════════════════════════════════════════════════════════════════
    def _detect_discovery_burst(self, snapshot: list[ProcessRecord],
                                pid_map: dict) -> Optional[HybridAlert]:
        """
        Behavioral: rapid execution of recon commands from the same parent.
        Smart filter: ignore bursts from known-safe parents (gnome-terminal
        running 'ls' is not an attack).
        """
        if not self._check_cooldown("discovery_burst"):
            return None

        now = datetime.now()
        window = now - timedelta(seconds=DISCOVERY_BURST_WINDOW)

        # Scan for recon commands in the snapshot
        for rec in snapshot:
            if rec.name and rec.name in DISCOVERY_COMMANDS:
                ppid = rec.ppid or 0
                parent = pid_map.get(ppid)

                # Skip if parent is a known safe process
                if parent and self._is_safe_process(parent):
                    continue

                try:
                    ts = datetime.fromtimestamp(rec.create_time)
                except (TypeError, OSError, ValueError):
                    continue

                if ts >= window:
                    self._recon_history[ppid].append((ts, rec.name))

        # Prune old entries and check for bursts
        for ppid in list(self._recon_history.keys()):
            entries = self._recon_history[ppid]
            entries[:] = [(ts, cmd) for ts, cmd in entries if ts >= window]
            if not entries:
                del self._recon_history[ppid]
                continue

            unique_cmds = set(cmd for _, cmd in entries)
            if len(unique_cmds) >= DISCOVERY_BURST_MIN_CMDS:
                del self._recon_history[ppid]

                # Get parent info
                parent = pid_map.get(ppid)
                parent_name = parent.name if parent else "unknown"
                parent_cmd = (parent.cmdline or "")[:60] if parent else ""

                score = 10.0 + len(unique_cmds) * 1.5
                reasons = [
                    f"{len(unique_cmds)} recon commands in {DISCOVERY_BURST_WINDOW}s",
                    f"Commands: {', '.join(sorted(unique_cmds))}",
                    f"Parent: {parent_name} (PID {ppid})",
                ]

                # Higher score if parent is bash/sh from unusual source
                if parent_name in ("bash", "sh", "dash") and parent:
                    if parent.cmdline and "/tmp/" in parent.cmdline:
                        score += 5.0
                        reasons.append("Parent shell running from /tmp")

                severity = self._score_to_severity(score)
                self._set_cooldown("discovery_burst")

                return HybridAlert(
                    attack_id="discovery_burst",
                    attack_name="Discovery Burst",
                    severity=severity,
                    mitre_id="T1082",
                    mitre_tactic="Discovery",
                    score=score,
                    details=f"Rapid recon from PPID {ppid} | " + " | ".join(reasons),
                    reasons=reasons,
                    pids=[ppid],
                    extra={"parent_pid": ppid, "commands": list(unique_cmds)},
                )

        return None

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 5 — Staging / Collection
    # ════════════════════════════════════════════════════════════════════
    def _detect_staging(self) -> Optional[HybridAlert]:
        """
        Behavioral: rapid creation of files in watched directories.
        Smart filter: only flag suspicious extensions or rapid bursts.
        """
        if not self._check_cooldown("staging_collection"):
            return None

        now = time.time()
        window_start = now - STAGING_TIME_WINDOW

        for watched_dir in STAGING_WATCH_DIRS:
            if not os.path.isdir(watched_dir):
                continue
            try:
                current = set(os.listdir(watched_dir))
            except PermissionError:
                continue

            prev = self._staging_snapshots.get(watched_dir, set())
            new_files = current - prev

            suspicious = []
            for fname in new_files:
                fpath = os.path.join(watched_dir, fname)
                _, ext = os.path.splitext(fname)
                if ext.lower() in STAGING_SUSPICIOUS_EXT:
                    suspicious.append(fpath)
                elif os.path.isfile(fpath):
                    try:
                        ctime = os.path.getctime(fpath)
                        if ctime >= window_start:
                            suspicious.append(fpath)
                    except OSError:
                        pass

            for fpath in suspicious:
                self._staging_new_files[watched_dir].append((now, fpath))

            # Prune old
            self._staging_new_files[watched_dir] = [
                (ts, fp) for ts, fp in self._staging_new_files[watched_dir]
                if ts >= window_start
            ]

            # Update snapshot
            self._staging_snapshots[watched_dir] = current

            recent = self._staging_new_files[watched_dir]
            if len(recent) >= STAGING_MIN_FILES:
                staged = [fp for _, fp in recent]
                self._staging_new_files[watched_dir] = []

                score = 12.0 + len(staged) * 0.5
                reasons = [
                    f"{len(staged)} suspicious files in {watched_dir}",
                    f"Within {STAGING_TIME_WINDOW}s window",
                    f"Files: {', '.join(os.path.basename(f) for f in staged[:5])}",
                ]

                severity = self._score_to_severity(score)
                self._set_cooldown("staging_collection")

                return HybridAlert(
                    attack_id="staging_collection",
                    attack_name="Staging / Collection",
                    severity=severity,
                    mitre_id="T1074.001",
                    mitre_tactic="Collection",
                    score=score,
                    details=f"Rapid file staging in {watched_dir} | "
                            + " | ".join(reasons),
                    reasons=reasons,
                    extra={"staged_files": staged, "directory": watched_dir},
                )

        return None

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 6 — Process Masquerading
    # ════════════════════════════════════════════════════════════════════
    def _detect_masquerading(self, snapshot: list[ProcessRecord]) -> Optional[HybridAlert]:
        """
        Behavioral: Process masquerading checks if a process uses a known 
        system-like name but runs from a suspicious path.
        """
        if not self._check_cooldown("masquerade_process"):
            return None

        best_score = 0.0
        best_reasons = []
        best_rec = None
        
        for rec in snapshot:
            name = (rec.name or "").lower()
            exe = rec.exe or ""
            cmdline = rec.cmdline or ""
            
            script_path = exe
            # If it's a script, psutil might report exe as /bin/bash but name as the script name
            # or it might report name as bash and script path in cmdline.
            # We should extract the script path from cmdline if it's executed via interpreter.
            if any(interp in exe for interp in ["/bash", "/sh", "/python", "/perl", "/ruby"]) and len(cmdline.split()) > 1:
                # Find the first argument that looks like a file path
                for arg in cmdline.split()[1:]:
                    if arg.startswith("/") or arg.startswith("./"):
                        script_path = arg
                        break
            
            # If name was reported as bash, extract true name from script_path
            if name in ("bash", "sh", "python", "python3") and script_path != exe:
                name = os.path.basename(script_path).lower()
            
            # If the name is in our masquerade list
            if name in MASQUERADE_NAMES:
                score = 0.0
                reasons = []
                
                # Check if it's executing from a user directory or /tmp
                if script_path.startswith(TARGET_HOME_DIR) or script_path.startswith("/tmp/"):
                    score += 15.0
                    reasons.append(f"Deceptive name '{name}' executing from {script_path}")
                
                # Check for hidden files/directories (starting with .)
                if "/." in script_path:
                    score += 5.0
                    reasons.append(f"Executable is hidden: {script_path}")
                    
                if score > best_score:
                    best_score = score
                    best_reasons = reasons
                    best_rec = rec
                    
        if best_score < 10.0:
            return None
            
        severity = self._score_to_severity(best_score)
        self._set_cooldown("masquerade_process")
        
        return HybridAlert(
            attack_id="masquerade_process",
            attack_name="Process Masquerading",
            severity=severity,
            mitre_id="T1036.005",
            mitre_tactic="Defense Evasion",
            score=best_score,
            details=f"Masquerading process {best_rec.name} (PID {best_rec.pid}) from unusual path",
            reasons=best_reasons,
            pids=[best_rec.pid],
            extra={"pid": best_rec.pid, "exe": best_rec.exe}
        )

    # ════════════════════════════════════════════════════════════════════
    #  DETECTOR 7 — Shell RC Persistence
    # ════════════════════════════════════════════════════════════════════
    def _detect_shell_rc_persistence(self) -> Optional[HybridAlert]:
        """
        Smart rule: Scan user shell configuration files for malicious markers.
        """
        if not self._check_cooldown("shell_rc_persist"):
            return None
            
        score = 0.0
        reasons = []
        bad_lines = []
        affected_files = []
        
        for rc_file in SHELL_RC_FILES:
            if not os.path.isfile(rc_file):
                continue
                
            try:
                with open(rc_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                            
                        # Check for known malicious markers
                        for marker in SHELL_RC_MARKERS:
                            if marker in line:
                                score += 15.0
                                reasons.append(f"Malicious marker '{marker}' found in {os.path.basename(rc_file)}")
                                bad_lines.append(line)
                                if rc_file not in affected_files:
                                    affected_files.append(rc_file)
                                break  # Check next line
            except Exception:
                pass
                
        if score < 10.0:
            return None
            
        severity = self._score_to_severity(score)
        self._set_cooldown("shell_rc_persist")
        
        return HybridAlert(
            attack_id="shell_rc_persist",
            attack_name="Shell RC Persistence",
            severity=severity,
            mitre_id="T1546.004",
            mitre_tactic="Persistence",
            score=score,
            details=f"Suspicious entries in shell configuration files | " + " | ".join(reasons),
            reasons=reasons,
            extra={"affected_files": affected_files, "bad_lines": bad_lines}
        )

    # ════════════════════════════════════════════════════════════════════
    #  Helpers
    # ════════════════════════════════════════════════════════════════════
    def _is_safe_process(self, rec: ProcessRecord) -> bool:
        """Check if a process is known-safe (should never trigger alerts)."""
        name = rec.name or ""
        if name in KNOWN_SAFE_PROCESSES:
            return True
        exe = rec.exe or ""
        if any(exe.startswith(prefix) for prefix in SAFE_EXE_PREFIXES):
            # But NOT if it's python running a user script
            cmdline = rec.cmdline or ""
            if "python" in name.lower() and TARGET_HOME_DIR in cmdline:
                return False
            return True
        return False

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 25:
            return "CRITICAL"
        if score >= 15:
            return "HIGH"
        if score >= 10:
            return "MEDIUM"
        if score >= 5:
            return "LOW"
        return "INFO"
