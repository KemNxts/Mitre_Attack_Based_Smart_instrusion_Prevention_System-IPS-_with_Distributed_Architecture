"""
=============================================================================
  Feature Extraction Module
  -------------------------
  Transforms raw ProcessRecords into numerical feature vectors suitable for
  anomaly scoring.

  Every feature is behavior-based — no filename or path hard-coding.

  Features computed per process:
  ──────────────────────────────────────────────────────────────────────────
  1.  tree_depth           — how deep this process sits in its ancestor chain
  2.  num_children         — direct child count
  3.  total_descendants    — recursive descendant count
  4.  rss_mb               — resident memory in MB
  5.  rss_ratio_to_parent  — RSS relative to parent (child/parent)
  6.  cpu_percent          — CPU utilisation
  7.  cmdline_length       — length of the full command line string
  8.  cmdline_entropy      — Shannon entropy of the command line
  9.  exe_path_depth       — number of '/' segments in the executable path
  10. exe_rarity           — 1 / (how many procs share this exe), higher=rarer
  11. parent_child_rarity  — 1 / (how common is this parent→child name pair)
  12. cmd_frequency        — how many procs share this exact command name
  13. age_seconds          — process lifetime since creation
  14. age_ratio_to_parent  — age relative to parent (child / parent)
  15. spawn_source_score   — 0=normal shell, 1=cron/systemd/sshd/at/…
  16. num_threads          — OS threads
  17. is_root              — running as root (uid 0)?
  ──────────────────────────────────────────────────────────────────────────
=============================================================================
"""

import math
import time
from collections import Counter
from typing import Optional

from hids.behavioral.collector import ProcessRecord


# ── Spawn sources that deserve higher scrutiny ─────────────────────────
_SUSPICIOUS_SPAWNERS = {
    "cron", "crond", "crontab", "atd", "at",
    "sshd", "systemd", "systemd-user",
    "nohup", "screen", "tmux",
}

# ── Typical system executables (large set; rarity is relative within snapshot)
# We don't need to hard-code "normal" — we calculate rarity statistically.


class FeatureVector:
    """Holds the extracted features for one process."""

    __slots__ = (
        "pid", "name", "exe", "cmdline",
        "tree_depth", "num_children", "total_descendants",
        "rss_mb", "rss_ratio_to_parent",
        "cpu_percent",
        "cmdline_length", "cmdline_entropy",
        "exe_path_depth", "exe_rarity",
        "parent_child_rarity",
        "cmd_frequency",
        "age_seconds", "age_ratio_to_parent",
        "spawn_source_score",
        "num_threads",
        "is_root",
    )

    def to_dict(self) -> dict:
        return {attr: getattr(self, attr, None) for attr in self.__slots__}

    def feature_values(self) -> list[float]:
        """Return only the numeric features as a flat list (for scoring)."""
        return [
            float(self.tree_depth or 0),
            float(self.num_children or 0),
            float(self.total_descendants or 0),
            float(self.rss_mb or 0),
            float(self.rss_ratio_to_parent or 0),
            float(self.cpu_percent or 0),
            float(self.cmdline_length or 0),
            float(self.cmdline_entropy or 0),
            float(self.exe_path_depth or 0),
            float(self.exe_rarity or 0),
            float(self.parent_child_rarity or 0),
            float(self.cmd_frequency or 0),
            float(self.age_seconds or 0),
            float(self.age_ratio_to_parent or 0),
            float(self.spawn_source_score or 0),
            float(self.num_threads or 0),
            float(self.is_root or 0),
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "tree_depth", "num_children", "total_descendants",
            "rss_mb", "rss_ratio_to_parent",
            "cpu_percent",
            "cmdline_length", "cmdline_entropy",
            "exe_path_depth", "exe_rarity",
            "parent_child_rarity",
            "cmd_frequency",
            "age_seconds", "age_ratio_to_parent",
            "spawn_source_score",
            "num_threads",
            "is_root",
        ]

    def __repr__(self):
        return f"<FeatureVector pid={self.pid} name={self.name!r}>"


class FeatureExtractor:
    """
    Extracts behavioral feature vectors from a list of ProcessRecords.

    All features are computed *relative to the snapshot* — rarity, frequency,
    and ratios are based on what's actually running, not hard-coded lists.
    """

    def extract(self, snapshot: list[ProcessRecord]) -> list[FeatureVector]:
        """
        Take a full process-table snapshot and return FeatureVectors
        for every process.
        """
        if not snapshot:
            return []

        # ── Pre-compute lookup tables from the snapshot ─────────────────
        pid_to_rec = {rec.pid: rec for rec in snapshot}
        name_counts = Counter(rec.name for rec in snapshot)
        exe_counts = Counter(rec.exe for rec in snapshot if rec.exe)

        # Parent-child name pair counts
        pc_pair_counts = Counter()
        for rec in snapshot:
            parent = pid_to_rec.get(rec.ppid)
            pname = parent.name if parent else "__orphan__"
            pc_pair_counts[(pname, rec.name)] += 1

        total_procs = len(snapshot)
        now = time.time()

        # ── Extract features for each process ───────────────────────────
        vectors: list[FeatureVector] = []
        for rec in snapshot:
            fv = FeatureVector()
            fv.pid = rec.pid
            fv.name = rec.name
            fv.exe = rec.exe
            fv.cmdline = rec.cmdline

            # 1) Tree depth
            fv.tree_depth = self._compute_tree_depth(rec, pid_to_rec)

            # 2-3) Children
            fv.num_children = rec.num_children or 0
            fv.total_descendants = self._count_descendants(rec.pid, pid_to_rec)

            # 4) Memory
            fv.rss_mb = (rec.rss_bytes or 0) / (1024 * 1024)

            # 5) Memory ratio to parent
            parent_rec = pid_to_rec.get(rec.ppid)
            if parent_rec and parent_rec.rss_bytes and parent_rec.rss_bytes > 0:
                fv.rss_ratio_to_parent = (rec.rss_bytes or 0) / parent_rec.rss_bytes
            else:
                fv.rss_ratio_to_parent = 1.0

            # 6) CPU
            fv.cpu_percent = rec.cpu_percent or 0.0

            # 7-8) Command-line analysis
            cmdline = rec.cmdline or ""
            fv.cmdline_length = len(cmdline)
            fv.cmdline_entropy = self._shannon_entropy(cmdline)

            # 9) Executable path depth
            exe_path = rec.exe or ""
            fv.exe_path_depth = exe_path.count("/") if exe_path else 0

            # 10) Executable rarity (inverse frequency within snapshot)
            exe_count = exe_counts.get(rec.exe, 0) if rec.exe else total_procs
            fv.exe_rarity = 1.0 / max(exe_count, 1)

            # 11) Parent-child rarity
            parent_name = parent_rec.name if parent_rec else "__orphan__"
            pair_count = pc_pair_counts.get((parent_name, rec.name), 0)
            fv.parent_child_rarity = 1.0 / max(pair_count, 1)

            # 12) Command name frequency
            fv.cmd_frequency = name_counts.get(rec.name, 0)

            # 13) Process age
            if rec.create_time and rec.create_time > 0:
                fv.age_seconds = now - rec.create_time
            else:
                fv.age_seconds = 0.0

            # 14) Age ratio to parent
            if parent_rec and parent_rec.create_time and parent_rec.create_time > 0:
                parent_age = now - parent_rec.create_time
                fv.age_ratio_to_parent = (
                    fv.age_seconds / parent_age if parent_age > 0 else 0.0
                )
            else:
                fv.age_ratio_to_parent = 0.0

            # 15) Spawn source suspicion
            fv.spawn_source_score = self._spawn_source_score(rec, pid_to_rec)

            # 16) Threads
            fv.num_threads = rec.num_threads or 0

            # 17) Root check
            fv.is_root = 1.0 if rec.username == "root" else 0.0

            vectors.append(fv)

        return vectors

    # ════════════════════════════════════════════════════════════════════
    #  Helper Methods
    # ════════════════════════════════════════════════════════════════════

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """
        Compute Shannon entropy of a string.
        High entropy → obfuscated / encoded command lines.
        """
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def _compute_tree_depth(rec: ProcessRecord,
                            pid_to_rec: dict[int, ProcessRecord],
                            max_depth: int = 32) -> int:
        """Walk up the parent chain to measure tree depth."""
        depth = 0
        current_ppid = rec.ppid
        visited = {rec.pid}
        while current_ppid and current_ppid > 1 and depth < max_depth:
            if current_ppid in visited:
                break  # cycle guard
            visited.add(current_ppid)
            parent = pid_to_rec.get(current_ppid)
            if not parent:
                break
            depth += 1
            current_ppid = parent.ppid
        return depth

    @staticmethod
    def _count_descendants(pid: int,
                           pid_to_rec: dict[int, ProcessRecord]) -> int:
        """BFS count of all recursive descendants."""
        count = 0
        queue = [pid]
        visited = {pid}
        while queue:
            current = queue.pop(0)
            rec = pid_to_rec.get(current)
            if rec and rec.child_pids:
                for cpid in rec.child_pids:
                    if cpid not in visited:
                        visited.add(cpid)
                        count += 1
                        queue.append(cpid)
        return count

    @staticmethod
    def _spawn_source_score(rec: ProcessRecord,
                            pid_to_rec: dict[int, ProcessRecord]) -> float:
        """
        Walk ancestors to determine if this process was spawned from a
        suspicious source (cron, sshd, systemd, etc.).
        Returns 0.0 (normal shell) or 1.0 (suspicious spawner in ancestry).
        """
        max_walk = 8
        current_ppid = rec.ppid
        visited = {rec.pid}
        for _ in range(max_walk):
            if current_ppid is None or current_ppid <= 1:
                break
            if current_ppid in visited:
                break
            visited.add(current_ppid)
            parent = pid_to_rec.get(current_ppid)
            if not parent:
                break
            if parent.name and parent.name.lower() in _SUSPICIOUS_SPAWNERS:
                return 1.0
            current_ppid = parent.ppid
        return 0.0
