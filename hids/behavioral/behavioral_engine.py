"""
=============================================================================
  Behavioral Detection Engine
  ----------------------------
  Top-level orchestrator for Phase 1 behavioral anomaly detection.

  Ties together:
      DataCollector  →  FeatureExtractor  →  AnomalyScorer
                                             ↕
                                       BaselineBuilder

  Operates in two modes:
      1. LEARNING   — collecting baseline data, no alerts
      2. MONITORING — scoring against baseline, emitting alerts

  Compatible with existing ThreatMemory and ResponseEngine:
      • Alerts carry an 'attack_id' derived from the behavioral category
      • Alerts carry 'severity' and 'details' just like the old detectors
      • ThreatMemory can track behavioral anomalies the same way

  Usage
  -----
      engine = BehavioralEngine()
      engine.start_learning(duration=120)   # learn for 2 minutes
      # ...later (auto-transitions or manual)...
      engine.start_monitoring()
      alerts = engine.get_alerts()

  Or from the existing HIDSCore, call engine.scan() which returns
  alert dicts with the same shape as the old DetectionEngine.
=============================================================================
"""

import os
import time
import threading
from datetime import datetime
from typing import Optional

from hids.config import DATA_DIR, SCAN_INTERVAL
from hids.behavioral.collector import DataCollector
from hids.behavioral.features import FeatureExtractor, FeatureVector
from hids.behavioral.baseline import BaselineBuilder, BaselineStats
from hids.behavioral.scorer import AnomalyScorer, AnomalyAlert


class BehavioralEngine:
    """
    Self-contained behavioral anomaly detection engine.

    Modes
    -----
    IDLE       — not running
    LEARNING   — collecting baseline data
    MONITORING — actively scoring and alerting
    """

    # ── Behavioral attack categories (replace old filename-based IDs) ──
    # These are derived from what the scorer finds, not from filenames.
    CATEGORY_MAP = {
        "tree_depth":          "anomalous_process_tree",
        "num_children":        "anomalous_process_tree",
        "total_descendants":   "anomalous_process_tree",
        "rss_mb":              "resource_abuse",
        "rss_ratio_to_parent": "resource_abuse",
        "cpu_percent":         "resource_abuse",
        "cmdline_length":      "suspicious_cmdline",
        "cmdline_entropy":     "suspicious_cmdline",
        "exe_path_depth":      "unusual_executable",
        "exe_rarity":          "unusual_executable",
        "parent_child_rarity": "unusual_parentchild",
        "cmd_frequency":       "rare_command",
        "age_seconds":         "process_timing",
        "age_ratio_to_parent": "process_timing",
        "spawn_source_score":  "suspicious_spawn_source",
        "num_threads":         "resource_abuse",
        "is_root":             "privilege_anomaly",
    }

    # Human-readable names for categories
    CATEGORY_NAMES = {
        "anomalous_process_tree": "Anomalous Process Tree",
        "resource_abuse":         "Resource Abuse",
        "suspicious_cmdline":     "Suspicious Command Line",
        "unusual_executable":     "Unusual Executable",
        "unusual_parentchild":    "Unusual Parent-Child Relationship",
        "rare_command":           "Rare Command Execution",
        "process_timing":         "Process Timing Anomaly",
        "suspicious_spawn_source":"Suspicious Spawn Source",
        "privilege_anomaly":      "Privilege Anomaly",
    }

    # MITRE ATT&CK approximate mapping for behavioral categories
    CATEGORY_MITRE = {
        "anomalous_process_tree": ("T1106", "Execution"),
        "resource_abuse":         ("T1496", "Impact"),
        "suspicious_cmdline":     ("T1059", "Execution"),
        "unusual_executable":     ("T1036", "Defense Evasion"),
        "unusual_parentchild":    ("T1055", "Defense Evasion"),
        "rare_command":           ("T1082", "Discovery"),
        "process_timing":         ("T1053", "Execution"),
        "suspicious_spawn_source":("T1053.003", "Persistence"),
        "privilege_anomaly":      ("T1548", "Privilege Escalation"),
    }

    def __init__(self, collect_interval: float = 2.0):
        self._collector = DataCollector(interval=collect_interval)
        self._extractor = FeatureExtractor()
        self._baseline = BaselineBuilder()
        self._scorer: Optional[AnomalyScorer] = None

        self._mode: str = "IDLE"    # IDLE / LEARNING / MONITORING
        self._lock = threading.Lock()

        self._learning_thread: Optional[threading.Thread] = None
        self._alerts_buffer: list[AnomalyAlert] = []
        self._alerts_lock = threading.Lock()

        # PIDs to suppress (our own, known system services)
        self._suppressed_pids: set[int] = {os.getpid()}

        # Cooldown: don't re-alert on the same PID within this window
        self._alert_cooldowns: dict[int, float] = {}
        self.ALERT_COOLDOWN = 30.0  # seconds

    # ════════════════════════════════════════════════════════════════════
    #  Mode Property
    # ════════════════════════════════════════════════════════════════════
    @property
    def mode(self) -> str:
        return self._mode

    # ════════════════════════════════════════════════════════════════════
    #  LEARNING MODE
    # ════════════════════════════════════════════════════════════════════
    def start_learning(self, duration: int = 120,
                       callback=None):
        """
        Begin learning normal behavior for *duration* seconds.
        After learning completes:
            • baseline is computed and saved
            • automatically transitions to MONITORING mode

        Parameters
        ----------
        duration : seconds to collect baseline data
        callback : optional function called when learning finishes
        """
        with self._lock:
            if self._mode != "IDLE":
                print(f"[Behavioral] Cannot start learning — currently in {self._mode} mode")
                return

            self._mode = "LEARNING"
            # Reset baseline
            self._baseline = BaselineBuilder()

        # Start collector
        self._collector.start()

        print(f"\033[96m[Behavioral] 🎓 LEARNING MODE — collecting baseline for {duration}s\033[0m")

        self._learning_thread = threading.Thread(
            target=self._learning_loop,
            args=(duration, callback),
            daemon=True,
            name="BehavioralLearning",
        )
        self._learning_thread.start()

    def _learning_loop(self, duration: int, callback):
        """Background thread: collect snapshots and feed to baseline builder."""
        start = time.time()
        snapshots_taken = 0

        while time.time() - start < duration and self._mode == "LEARNING":
            snapshot = self._collector.latest_snapshot()
            if snapshot:
                vectors = self._extractor.extract(snapshot)
                self._baseline.add_snapshot(vectors)
                snapshots_taken += 1
                elapsed = int(time.time() - start)
                print(
                    f"\033[96m[Baseline] snapshot #{snapshots_taken} | "
                    f"{len(vectors)} processes | {elapsed}s/{duration}s\033[0m"
                )
            time.sleep(SCAN_INTERVAL)

        # Learning complete — compute and save baseline
        stats = self._baseline.compute()
        self._baseline.save()

        print(f"\033[92m[Behavioral] ✅ Baseline built from {snapshots_taken} snapshots\033[0m")
        print(f"\033[92m[Behavioral]    Saved to {self._baseline._filepath}\033[0m")

        # Print baseline summary
        self._print_baseline_summary(stats)

        # Auto-transition to monitoring
        with self._lock:
            self._mode = "IDLE"
        self.start_monitoring()

        if callback:
            callback()

    def _print_baseline_summary(self, stats: BaselineStats):
        """Print a human-readable baseline summary."""
        print("\n" + "=" * 65)
        print("  📊 BASELINE SUMMARY")
        print("=" * 65)
        for fname in FeatureVector.feature_names():
            s = stats.get(fname)
            print(
                f"  {fname:30s}  mean={s['mean']:10.2f}  "
                f"std={s['std']:8.2f}  p95={s['p95']:10.2f}  n={s['n']}"
            )
        print("=" * 65 + "\n")

    # ════════════════════════════════════════════════════════════════════
    #  MONITORING MODE
    # ════════════════════════════════════════════════════════════════════
    def start_monitoring(self):
        """
        Start monitoring mode.  Loads baseline if available.
        If no baseline exists, uses heuristic-only scoring.
        """
        with self._lock:
            if self._mode == "MONITORING":
                return
            if self._mode == "LEARNING":
                print("[Behavioral] Cannot monitor — still learning")
                return
            self._mode = "MONITORING"

        # Ensure collector is running
        if not self._collector.is_running:
            self._collector.start()

        # Load or use existing baseline
        if self._baseline.has_baseline():
            if self._baseline.get_stats().is_empty:
                self._baseline = BaselineBuilder.load()
            stats = self._baseline.get_stats()
            self._scorer = AnomalyScorer(baseline=stats)
            print("\033[92m[Behavioral] 🔍 MONITORING MODE — using learned baseline\033[0m")
        else:
            self._scorer = AnomalyScorer(baseline=None)
            print("\033[93m[Behavioral] 🔍 MONITORING MODE — no baseline, using heuristics only\033[0m")

    def stop(self):
        """Stop all activity."""
        with self._lock:
            self._mode = "IDLE"
        self._collector.stop()

    # ════════════════════════════════════════════════════════════════════
    #  SCAN — Compatible with old DetectionEngine.scan()
    # ════════════════════════════════════════════════════════════════════
    def scan(self) -> list[dict]:
        """
        Perform one behavioral scan cycle.
        Returns a list of alert dicts compatible with the existing
        ThreatMemory / ResponseEngine / EventLogger interface.

        Each dict has:
            attack_id     — behavioral category id
            attack_name   — human-readable category name
            severity      — LOW / MEDIUM / HIGH / CRITICAL
            mitre_id      — approximate MITRE mapping
            mitre_tactic  — MITRE tactic
            details       — human-readable summary
            pid           — offending PID
            score         — anomaly score
            features      — contributing features
        """
        if self._mode != "MONITORING" or not self._scorer:
            return []

        # Get latest snapshot
        snapshot = self._collector.latest_snapshot()
        if not snapshot:
            return []

        # Extract features
        vectors = self._extractor.extract(snapshot)

        # Score
        alerts = self._scorer.score_snapshot(vectors)

        # Filter: cooldowns + suppressed PIDs
        now = time.time()
        results = []
        for alert in alerts:
            if alert.pid in self._suppressed_pids:
                continue
            last_alert = self._alert_cooldowns.get(alert.pid, 0)
            if now - last_alert < self.ALERT_COOLDOWN:
                continue
            self._alert_cooldowns[alert.pid] = now

            # Determine primary category from top contributing feature
            category = self._categorize_alert(alert)
            mitre_id, mitre_tactic = self.CATEGORY_MITRE.get(
                category, ("T1204", "Execution")
            )

            results.append({
                "attack_id": category,
                "attack_name": self.CATEGORY_NAMES.get(category, category),
                "severity": alert.severity,
                "mitre_id": mitre_id,
                "mitre_tactic": mitre_tactic,
                "details": alert.summary(),
                "pid": alert.pid,
                "score": alert.score,
                "features": alert.contributing_features,
            })

            # Store in buffer for external query
            with self._alerts_lock:
                self._alerts_buffer.append(alert)
                # Keep buffer bounded
                if len(self._alerts_buffer) > 200:
                    self._alerts_buffer = self._alerts_buffer[-200:]

        return results

    def _categorize_alert(self, alert: AnomalyAlert) -> str:
        """
        Determine the primary behavioral category for an alert
        based on which feature contributed most to its score.
        """
        if not alert.contributing_features:
            return "resource_abuse"

        # Find the top contributing feature (by contribution value)
        top = max(alert.contributing_features,
                  key=lambda f: f.get("contribution", 0))
        feature_name = top["feature"]

        # Handle PATTERN: prefixed features
        if feature_name.startswith("PATTERN:"):
            pattern = feature_name.split(":", 1)[1]
            pattern_map = {
                "deep_tree_many_children":   "anomalous_process_tree",
                "high_mem_many_descendants": "resource_abuse",
                "high_entropy_rare_exe":     "suspicious_cmdline",
                "suspicious_spawn_anomalous":"suspicious_spawn_source",
                "young_resource_heavy":       "resource_abuse",
            }
            return pattern_map.get(pattern, "resource_abuse")

        return self.CATEGORY_MAP.get(feature_name, "resource_abuse")

    # ════════════════════════════════════════════════════════════════════
    #  Query API
    # ════════════════════════════════════════════════════════════════════
    def get_recent_alerts(self, n: int = 20) -> list[AnomalyAlert]:
        """Return the N most recent anomaly alerts."""
        with self._alerts_lock:
            return list(self._alerts_buffer[-n:])[::-1]

    def get_baseline_stats(self) -> Optional[BaselineStats]:
        """Return the current baseline stats (or None)."""
        if self._baseline:
            stats = self._baseline.get_stats()
            return stats if not stats.is_empty else None
        return None

    def get_status(self) -> dict:
        """Return current engine status for external monitoring."""
        return {
            "mode": self._mode,
            "collector_running": self._collector.is_running,
            "snapshots_collected": self._collector.snapshot_count(),
            "baseline_exists": self._baseline.has_baseline() if self._baseline else False,
            "baseline_snapshots": self._baseline.snapshot_count if self._baseline else 0,
            "total_alerts": len(self._alerts_buffer),
        }
