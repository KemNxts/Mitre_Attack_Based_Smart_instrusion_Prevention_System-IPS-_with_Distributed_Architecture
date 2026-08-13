"""
=============================================================================
  Baseline Builder
  ----------------
  Records what "normal" looks like on this host by collecting multiple
  snapshots of behavioral features and computing per-feature statistics:
      mean, standard deviation, min, max, percentile_95

  These statistics are used by the AnomalyScorer to flag deviations.

  Persistence
  -----------
  The baseline is saved as JSON (human-readable, easy to inspect) and
  can be loaded on restart so you don't need to re-learn every time.

  Usage
  -----
      builder = BaselineBuilder()
      # Feed it snapshots (list[FeatureVector]) over time
      builder.add_snapshot(feature_vectors)
      builder.add_snapshot(feature_vectors)
      ...
      builder.save("baseline.json")

      # Later
      baseline = BaselineBuilder.load("baseline.json")
      stats = baseline.get_stats()
=============================================================================
"""

import json
import os
import math
import threading
from collections import defaultdict
from typing import Optional

from hids.config import DATA_DIR
from hids.behavioral.features import FeatureVector


DEFAULT_BASELINE_PATH = os.path.join(DATA_DIR, "baseline.json")


class BaselineStats:
    """
    Per-feature statistics computed from observed normal behavior.

    For each of the 17 features, stores:
        mean, std, min, max, p95, sample_count
    """

    def __init__(self, stats: dict[str, dict] | None = None):
        # stats[feature_name] = {"mean": ..., "std": ..., "min": ..., "max": ..., "p95": ..., "n": ...}
        self.stats: dict[str, dict] = stats or {}

    def get(self, feature_name: str) -> dict:
        """Return stats for one feature, or defaults if not yet learned."""
        return self.stats.get(feature_name, {
            "mean": 0.0, "std": 1.0, "min": 0.0, "max": 0.0, "p95": 0.0, "n": 0
        })

    def z_score(self, feature_name: str, value: float) -> float:
        """
        Compute how many standard deviations *value* is from the baseline mean.
        |z| > 2  →  unusual
        |z| > 3  →  highly anomalous
        """
        s = self.get(feature_name)
        std = s["std"]
        if std == 0:
            # If std is 0 all observed values were identical;
            # any deviation is infinite, but cap at 5 for scoring
            return 0.0 if value == s["mean"] else 5.0
        return (value - s["mean"]) / std

    def is_above_p95(self, feature_name: str, value: float) -> bool:
        """Return True if value exceeds the 95th-percentile baseline."""
        return value > self.get(feature_name).get("p95", float("inf"))

    def to_dict(self) -> dict:
        return self.stats

    @property
    def is_empty(self) -> bool:
        return len(self.stats) == 0


class BaselineBuilder:
    """
    Accumulates feature observations and computes statistical baselines.

    Thread-safe: can be fed from a background collection thread.
    """

    def __init__(self, filepath: str = DEFAULT_BASELINE_PATH):
        self._filepath = filepath
        self._lock = threading.Lock()

        # Accumulate raw values per feature name
        # _observations[feature_name] = [v1, v2, v3, ...]
        self._observations: dict[str, list[float]] = defaultdict(list)

        # Also track per-process-name observations for rarity baselines
        # _name_counts[process_name] = total_times_seen
        self._name_counts: dict[str, int] = defaultdict(int)

        # Per parent→child pair counts
        self._pc_pair_counts: dict[str, int] = defaultdict(int)

        self._snapshot_count = 0
        self._computed_stats: Optional[BaselineStats] = None

    # ── Feed data ───────────────────────────────────────────────────────
    def add_snapshot(self, vectors: list[FeatureVector]):
        """
        Incorporate one snapshot's worth of feature vectors into the
        accumulator.  Call this repeatedly during baseline-learning.
        """
        with self._lock:
            names = FeatureVector.feature_names()
            for fv in vectors:
                values = fv.feature_values()
                for name, val in zip(names, values):
                    self._observations[name].append(val)

                # Track process name frequency
                if fv.name:
                    self._name_counts[fv.name] += 1

                # Track parent-child pairs (stored in feature vector metadata)
                # We don't have parent_name directly in FV, but we stored it
                # during extraction; we'll track exe combos instead via name
                # This isn't critical — rarity is computed from snapshots anyway

            self._snapshot_count += 1
            # Invalidate precomputed stats
            self._computed_stats = None

    # ── Compute stats ───────────────────────────────────────────────────
    def compute(self) -> BaselineStats:
        """
        Compute per-feature statistics from all accumulated observations.
        """
        with self._lock:
            stats = {}
            for fname, values in self._observations.items():
                if not values:
                    continue
                n = len(values)
                mean = sum(values) / n
                variance = sum((v - mean) ** 2 for v in values) / max(n - 1, 1)
                std = math.sqrt(variance)
                sorted_vals = sorted(values)
                p95_idx = min(int(n * 0.95), n - 1)

                stats[fname] = {
                    "mean": round(mean, 6),
                    "std": round(std, 6),
                    "min": round(sorted_vals[0], 6),
                    "max": round(sorted_vals[-1], 6),
                    "p95": round(sorted_vals[p95_idx], 6),
                    "n": n,
                }

            self._computed_stats = BaselineStats(stats)
            return self._computed_stats

    def get_stats(self) -> BaselineStats:
        """Return computed stats (compute if needed)."""
        if self._computed_stats is None:
            return self.compute()
        return self._computed_stats

    @property
    def snapshot_count(self) -> int:
        with self._lock:
            return self._snapshot_count

    @property
    def observation_count(self) -> int:
        with self._lock:
            total = 0
            for vals in self._observations.values():
                total += len(vals)
            return total

    # ── Persistence ─────────────────────────────────────────────────────
    def save(self, filepath: str | None = None):
        """Save the computed baseline to a JSON file."""
        path = filepath or self._filepath
        stats = self.get_stats()
        payload = {
            "version": 1,
            "snapshot_count": self._snapshot_count,
            "total_observations": self.observation_count,
            "process_name_counts": dict(self._name_counts),
            "feature_stats": stats.to_dict(),
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)

    @classmethod
    def load(cls, filepath: str = DEFAULT_BASELINE_PATH) -> "BaselineBuilder":
        """Load a previously saved baseline."""
        builder = cls(filepath)
        if not os.path.exists(filepath):
            return builder

        with open(filepath, "r") as f:
            data = json.load(f)

        builder._snapshot_count = data.get("snapshot_count", 0)
        builder._name_counts = defaultdict(int, data.get("process_name_counts", {}))
        feature_stats = data.get("feature_stats", {})
        builder._computed_stats = BaselineStats(feature_stats)

        # We don't restore raw _observations (would be huge);
        # the computed stats are sufficient for scoring.
        return builder

    def has_baseline(self) -> bool:
        """Return True if we have a computed or loaded baseline."""
        if self._computed_stats and not self._computed_stats.is_empty:
            return True
        return os.path.exists(self._filepath)

    def reset(self):
        """Clear all accumulated data."""
        with self._lock:
            self._observations.clear()
            self._name_counts.clear()
            self._pc_pair_counts.clear()
            self._snapshot_count = 0
            self._computed_stats = None
