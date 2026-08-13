"""
=============================================================================
  Behavioral Data Collector
  -------------------------
  Continuously snapshots every process on the system via psutil and stores
  structured records.  No filename matching — captures raw behavioral data
  that downstream modules use for feature extraction and scoring.

  Collected fields per process:
      pid, ppid, name, exe, cmdline, username, create_time,
      rss_bytes, vms_bytes, cpu_percent, num_threads, status,
      num_children, child_pids, parent_name, parent_exe

  Thread-safe: a background thread fills a ring-buffer of snapshots.
=============================================================================
"""

import os
import time
import threading
from datetime import datetime
from collections import deque
from typing import Optional

import psutil


class ProcessRecord:
    """One point-in-time observation of a single process."""

    __slots__ = (
        "pid", "ppid", "name", "exe", "cmdline", "username",
        "create_time", "snapshot_time",
        "rss_bytes", "vms_bytes", "cpu_percent", "num_threads",
        "status", "num_children", "child_pids",
        "parent_name", "parent_exe",
    )

    def __init__(self):
        for attr in self.__slots__:
            setattr(self, attr, None)

    def to_dict(self) -> dict:
        return {attr: getattr(self, attr) for attr in self.__slots__}

    def __repr__(self):
        return f"<ProcessRecord pid={self.pid} name={self.name!r}>"


class DataCollector:
    """
    Periodically scans all running processes and stores ProcessRecords.

    Usage
    -----
        collector = DataCollector(interval=2.0)
        collector.start()
        # ... later ...
        snapshot = collector.latest_snapshot()   # list[ProcessRecord]
        collector.stop()
    """

    # PIDs we never want to alert on (kernel, our own HIDS, etc.)
    _SKIP_PIDS = {0, 1, 2}

    def __init__(self, interval: float = 2.0, history_size: int = 60):
        """
        Parameters
        ----------
        interval     : seconds between full process-table scans
        history_size : number of past snapshots to keep in memory
        """
        self._interval = interval
        self._history: deque[list[ProcessRecord]] = deque(maxlen=history_size)
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._own_pid = os.getpid()

    # ── Lifecycle ───────────────────────────────────────────────────────
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="DataCollector")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Main collection loop ────────────────────────────────────────────
    def _loop(self):
        while self._running:
            try:
                snapshot = self._take_snapshot()
                with self._lock:
                    self._history.append(snapshot)
            except Exception:
                pass  # never crash the collector
            time.sleep(self._interval)

    def _take_snapshot(self) -> list[ProcessRecord]:
        """Iterate the entire process table and build ProcessRecords."""
        now = datetime.now().isoformat()
        records: list[ProcessRecord] = []

        # Pre-build a quick pid→proc lookup for parent enrichment
        proc_map: dict[int, psutil.Process] = {}
        for p in psutil.process_iter():
            proc_map[p.pid] = p

        for proc in proc_map.values():
            if proc.pid in self._SKIP_PIDS or proc.pid == self._own_pid:
                continue
            rec = self._read_process(proc, now, proc_map)
            if rec is not None:
                records.append(rec)

        return records

    def _read_process(self, proc: psutil.Process, now: str,
                      proc_map: dict) -> Optional[ProcessRecord]:
        """Safely read all fields for one process."""
        rec = ProcessRecord()
        try:
            # Using oneshot context for efficiency (single /proc read)
            with proc.oneshot():
                rec.pid = proc.pid
                rec.snapshot_time = now

                try:
                    rec.ppid = proc.ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.ppid = -1

                try:
                    rec.name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.name = ""

                try:
                    rec.exe = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.exe = ""

                try:
                    rec.cmdline = " ".join(proc.cmdline())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.cmdline = ""

                try:
                    rec.username = proc.username()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.username = ""

                try:
                    rec.create_time = proc.create_time()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.create_time = 0.0

                try:
                    mem = proc.memory_info()
                    rec.rss_bytes = mem.rss
                    rec.vms_bytes = mem.vms
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.rss_bytes = 0
                    rec.vms_bytes = 0

                try:
                    rec.cpu_percent = proc.cpu_percent(interval=0)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.cpu_percent = 0.0

                try:
                    rec.num_threads = proc.num_threads()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.num_threads = 0

                try:
                    rec.status = proc.status()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.status = ""

                # Children
                try:
                    children = proc.children(recursive=False)
                    rec.num_children = len(children)
                    rec.child_pids = [c.pid for c in children]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rec.num_children = 0
                    rec.child_pids = []

                # Parent enrichment
                parent = proc_map.get(rec.ppid)
                if parent:
                    try:
                        rec.parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        rec.parent_name = ""
                    try:
                        rec.parent_exe = parent.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        rec.parent_exe = ""
                else:
                    rec.parent_name = ""
                    rec.parent_exe = ""

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None  # process vanished while reading

        return rec

    # ── Public query API ────────────────────────────────────────────────
    def latest_snapshot(self) -> list[ProcessRecord]:
        """Return the most recent process-table snapshot (or [])."""
        with self._lock:
            if self._history:
                return list(self._history[-1])
            return []

    def all_snapshots(self) -> list[list[ProcessRecord]]:
        """Return all stored snapshots (oldest first)."""
        with self._lock:
            return [list(s) for s in self._history]

    def snapshot_count(self) -> int:
        with self._lock:
            return len(self._history)

    def flatten_recent(self, n: int = 5) -> list[ProcessRecord]:
        """Flatten the last *n* snapshots into a single list."""
        with self._lock:
            out = []
            for snap in list(self._history)[-n:]:
                out.extend(snap)
            return out
