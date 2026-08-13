"""
=============================================================================
  Behavioral Anomaly Scorer
  -------------------------
  Scores each process using a weighted combination of z-score deviations
  from the learned baseline.  Higher score = more anomalous.

  This is a *rule + statistical* hybrid scorer (Phase 1).
  Phase 2 will layer an ML model on top of the same feature vectors.

  Scoring Strategy
  ================
  For each FeatureVector we compute a weighted anomaly score:

      score = Σ  weight_i × |z_score_i|    (for z > threshold)

  Plus bonus points for specific behavioral red-flags:
      • process tree unusually deep or wide          (+2.0 each)
      • memory >> baseline 95th percentile           (+3.0)
      • command-line entropy very high                (+1.5)
      • rare parent-child relationship                (+2.0)
      • rare executable                               (+1.5)
      • spawned from cron/systemd/sshd with oddities  (+2.0)

  Alert thresholds:
      score >= 5.0   →  LOW      anomaly
      score >= 10.0  →  MEDIUM   anomaly
      score >= 15.0  →  HIGH     anomaly
      score >= 25.0  →  CRITICAL anomaly
=============================================================================
"""

from dataclasses import dataclass, field
from typing import Optional

from hids.behavioral.features import FeatureVector
from hids.behavioral.baseline import BaselineStats


# ── Feature weights (how important each feature is for anomaly detection) ──
FEATURE_WEIGHTS = {
    "tree_depth":           1.2,
    "num_children":         1.5,
    "total_descendants":    1.5,
    "rss_mb":               2.0,
    "rss_ratio_to_parent":  1.8,
    "cpu_percent":          1.5,
    "cmdline_length":       0.8,
    "cmdline_entropy":      1.2,
    "exe_path_depth":       0.5,
    "exe_rarity":           1.5,
    "parent_child_rarity":  2.0,
    "cmd_frequency":        0.3,    # lower freq = rarer command — inverted during scoring
    "age_seconds":          0.5,
    "age_ratio_to_parent":  0.7,
    "spawn_source_score":   2.0,
    "num_threads":          0.8,
    "is_root":              1.0,
}

# ── Z-score threshold: deviations below this are considered normal ─────
Z_THRESHOLD = 2.0

# ── Alert severity thresholds ──────────────────────────────────────────
SEVERITY_THRESHOLDS = {
    "LOW":      5.0,
    "MEDIUM":  10.0,
    "HIGH":    15.0,
    "CRITICAL": 25.0,
}


@dataclass
class AnomalyAlert:
    """One behavioral anomaly detection result."""
    pid: int
    name: str
    exe: str
    cmdline: str
    score: float
    severity: str                            # LOW / MEDIUM / HIGH / CRITICAL
    contributing_features: list[dict] = field(default_factory=list)
    # Each entry: {"feature": name, "value": val, "z_score": z, "contribution": weighted_z}

    def summary(self) -> str:
        """One-line human-readable summary."""
        top = sorted(self.contributing_features, key=lambda x: x["contribution"], reverse=True)[:3]
        reasons = ", ".join(f'{f["feature"]}(z={f["z_score"]:.1f})' for f in top)
        return (
            f"[{self.severity}] PID {self.pid} ({self.name}) "
            f"score={self.score:.1f}  top_reasons: {reasons}"
        )

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline[:200],
            "score": round(self.score, 2),
            "severity": self.severity,
            "contributing_features": self.contributing_features,
        }


class AnomalyScorer:
    """
    Scores FeatureVectors against a BaselineStats and produces AnomalyAlerts
    for processes that deviate significantly from normal.
    """

    def __init__(self, baseline: Optional[BaselineStats] = None,
                 alert_threshold: float = 5.0):
        """
        Parameters
        ----------
        baseline        : precomputed baseline stats (can be set later)
        alert_threshold : minimum score to generate an alert
        """
        self.baseline = baseline
        self.alert_threshold = alert_threshold
        self._weights = dict(FEATURE_WEIGHTS)

    def set_baseline(self, baseline: BaselineStats):
        """Update the baseline (e.g. after learning phase completes)."""
        self.baseline = baseline

    # ════════════════════════════════════════════════════════════════════
    #  Score a full snapshot
    # ════════════════════════════════════════════════════════════════════
    def score_snapshot(self, vectors: list[FeatureVector]) -> list[AnomalyAlert]:
        """
        Score every process in a snapshot.
        Returns only those above the alert threshold, sorted by score desc.
        """
        alerts = []
        for fv in vectors:
            alert = self.score_process(fv)
            if alert:
                alerts.append(alert)
        alerts.sort(key=lambda a: a.score, reverse=True)
        return alerts

    # ════════════════════════════════════════════════════════════════════
    #  Score a single process
    # ════════════════════════════════════════════════════════════════════
    def score_process(self, fv: FeatureVector) -> Optional[AnomalyAlert]:
        """
        Compute anomaly score for one process.
        Returns an AnomalyAlert if score >= threshold, else None.
        """
        if not self.baseline or self.baseline.is_empty:
            # No baseline yet — fall back to heuristic-only scoring
            return self._heuristic_score(fv)

        names = FeatureVector.feature_names()
        values = fv.feature_values()

        total_score = 0.0
        contributions = []

        for fname, value in zip(names, values):
            weight = self._weights.get(fname, 1.0)
            z = self.baseline.z_score(fname, value)
            abs_z = abs(z)

            # Only count deviations above the threshold
            if abs_z > Z_THRESHOLD:
                # For "cmd_frequency": low frequency = rare = suspicious
                # z_score will be negative when freq is below mean, which is
                # what we want (we take abs), so no inversion needed.
                contribution = weight * (abs_z - Z_THRESHOLD)
                total_score += contribution

                contributions.append({
                    "feature": fname,
                    "value": round(value, 4),
                    "baseline_mean": self.baseline.get(fname).get("mean", 0),
                    "baseline_std": self.baseline.get(fname).get("std", 0),
                    "z_score": round(z, 2),
                    "contribution": round(contribution, 2),
                })

        # ── Bonus points for behavioral red-flags ───────────────────
        total_score += self._bonus_score(fv, contributions)

        if total_score < self.alert_threshold:
            return None

        severity = self._classify_severity(total_score)

        return AnomalyAlert(
            pid=fv.pid,
            name=fv.name or "",
            exe=fv.exe or "",
            cmdline=fv.cmdline or "",
            score=round(total_score, 2),
            severity=severity,
            contributing_features=contributions,
        )

    # ════════════════════════════════════════════════════════════════════
    #  Bonus scoring for specific behavioral patterns
    # ════════════════════════════════════════════════════════════════════
    def _bonus_score(self, fv: FeatureVector,
                     contributions: list[dict]) -> float:
        """
        Add bonus points for multi-feature behavioral patterns that
        indicate a real threat, beyond individual z-scores.
        """
        bonus = 0.0

        # ── Deep process tree + many children = suspicious ──────────
        tree_d = fv.tree_depth or 0
        n_children = fv.num_children or 0
        if tree_d >= 4 and n_children >= 3:
            bonus += 2.0
            contributions.append({
                "feature": "PATTERN:deep_tree_many_children",
                "value": f"depth={tree_d}, children={n_children}",
                "z_score": 0,
                "baseline_mean": 0,
                "baseline_std": 0,
                "contribution": 2.0,
            })

        # ── High memory + many descendants = resource abuse ─────────
        rss = fv.rss_mb or 0
        descendants = fv.total_descendants or 0
        if rss > 100 and descendants >= 2:
            bonus += 3.0
            contributions.append({
                "feature": "PATTERN:high_mem_many_descendants",
                "value": f"rss={rss:.0f}MB, descendants={descendants}",
                "z_score": 0,
                "baseline_mean": 0,
                "baseline_std": 0,
                "contribution": 3.0,
            })

        # ── High cmdline entropy + rare exe = evasion ───────────────
        entropy = fv.cmdline_entropy or 0
        exe_rarity = fv.exe_rarity or 0
        if entropy > 4.0 and exe_rarity > 0.5:
            bonus += 1.5
            contributions.append({
                "feature": "PATTERN:high_entropy_rare_exe",
                "value": f"entropy={entropy:.2f}, rarity={exe_rarity:.2f}",
                "z_score": 0,
                "baseline_mean": 0,
                "baseline_std": 0,
                "contribution": 1.5,
            })

        # ── Suspicious spawn source + unusual behavior ──────────────
        if (fv.spawn_source_score or 0) >= 1.0:
            # Cron/systemd/sshd spawned process that also has anomalous features
            anomalous_features = sum(1 for c in contributions
                                     if c.get("z_score", 0) != 0 and abs(c["z_score"]) > 2)
            if anomalous_features >= 2:
                bonus += 2.0
                contributions.append({
                    "feature": "PATTERN:suspicious_spawn_anomalous",
                    "value": f"spawner=cron/systemd/sshd, anomalous_features={anomalous_features}",
                    "z_score": 0,
                    "baseline_mean": 0,
                    "baseline_std": 0,
                    "contribution": 2.0,
                })

        # ── Very young process with high resource usage ─────────────
        age = fv.age_seconds or 0
        cpu = fv.cpu_percent or 0
        if age < 10 and (rss > 50 or cpu > 30):
            bonus += 2.0
            contributions.append({
                "feature": "PATTERN:young_resource_heavy",
                "value": f"age={age:.0f}s, rss={rss:.0f}MB, cpu={cpu:.1f}%",
                "z_score": 0,
                "baseline_mean": 0,
                "baseline_std": 0,
                "contribution": 2.0,
            })

        return bonus

    # ════════════════════════════════════════════════════════════════════
    #  Heuristic-only scoring (before baseline is trained)
    # ════════════════════════════════════════════════════════════════════
    def _heuristic_score(self, fv: FeatureVector) -> Optional[AnomalyAlert]:
        """
        Fallback scoring when no baseline exists.
        Uses absolute thresholds based on general Linux process behavior.
        """
        score = 0.0
        contributions = []

        # Deep tree
        if (fv.tree_depth or 0) >= 5:
            s = (fv.tree_depth - 4) * 1.5
            score += s
            contributions.append({
                "feature": "tree_depth",
                "value": fv.tree_depth,
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": round(s, 2),
            })

        # Many children
        if (fv.num_children or 0) >= 5:
            s = (fv.num_children - 4) * 1.5
            score += s
            contributions.append({
                "feature": "num_children",
                "value": fv.num_children,
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": round(s, 2),
            })

        # Many descendants
        if (fv.total_descendants or 0) >= 8:
            s = (fv.total_descendants - 7) * 1.2
            score += s
            contributions.append({
                "feature": "total_descendants",
                "value": fv.total_descendants,
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": round(s, 2),
            })

        # High memory (>200MB for a single process is notable)
        if (fv.rss_mb or 0) > 200:
            s = (fv.rss_mb - 200) / 50 * 2.0
            score += s
            contributions.append({
                "feature": "rss_mb",
                "value": round(fv.rss_mb, 1),
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": round(s, 2),
            })

        # High CPU
        if (fv.cpu_percent or 0) > 50:
            s = (fv.cpu_percent - 50) / 25 * 1.5
            score += s
            contributions.append({
                "feature": "cpu_percent",
                "value": fv.cpu_percent,
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": round(s, 2),
            })

        # Very high cmdline entropy
        if (fv.cmdline_entropy or 0) > 4.5:
            s = (fv.cmdline_entropy - 4.5) * 2.0
            score += s
            contributions.append({
                "feature": "cmdline_entropy",
                "value": round(fv.cmdline_entropy, 2),
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": round(s, 2),
            })

        # High rarity scores
        if (fv.exe_rarity or 0) > 0.5:
            score += 1.5
            contributions.append({
                "feature": "exe_rarity",
                "value": round(fv.exe_rarity, 3),
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": 1.5,
            })

        if (fv.parent_child_rarity or 0) > 0.5:
            score += 1.5
            contributions.append({
                "feature": "parent_child_rarity",
                "value": round(fv.parent_child_rarity, 3),
                "z_score": 0,
                "baseline_mean": "N/A (no baseline)",
                "baseline_std": "N/A",
                "contribution": 1.5,
            })

        # Bonus patterns (reuse existing method)
        score += self._bonus_score(fv, contributions)

        if score < self.alert_threshold:
            return None

        severity = self._classify_severity(score)
        return AnomalyAlert(
            pid=fv.pid,
            name=fv.name or "",
            exe=fv.exe or "",
            cmdline=fv.cmdline or "",
            score=round(score, 2),
            severity=severity,
            contributing_features=contributions,
        )

    # ════════════════════════════════════════════════════════════════════
    #  Severity classification
    # ════════════════════════════════════════════════════════════════════
    @staticmethod
    def _classify_severity(score: float) -> str:
        if score >= SEVERITY_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        if score >= SEVERITY_THRESHOLDS["HIGH"]:
            return "HIGH"
        if score >= SEVERITY_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        if score >= SEVERITY_THRESHOLDS["LOW"]:
            return "LOW"
        return "INFO"
