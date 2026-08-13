"""
=============================================================================
  HIDS Socket Client
  ------------------
  Maintains a non-blocking background queue to forward telemetry events
  to the Central Server via TCP. Reconnects and retries on failure without
  blocking the main detection engine.
=============================================================================
"""

import socket
import json
import time
import threading
import queue

from hids.config import (
    HIDS_SOCKET_ENABLED,
    HIDS_SERVER_HOST,
    HIDS_SERVER_PORT,
    HIDS_SOCKET_RECONNECT_INTERVAL,
    HIDS_SOCKET_QUEUE_LIMIT
)

class SocketClient:
    def __init__(self):
        self.enabled = HIDS_SOCKET_ENABLED
        self.host = HIDS_SERVER_HOST
        self.port = HIDS_SERVER_PORT
        self.reconnect_interval = HIDS_SOCKET_RECONNECT_INTERVAL
        
        # In-memory queue for offline buffering
        self.queue = queue.Queue(maxsize=HIDS_SOCKET_QUEUE_LIMIT)
        
        self._running = False
        self._thread = None
        self._socket = None

    def start(self):
        """Start the background worker thread."""
        if not self.enabled or self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="SocketClientWorker")
        self._thread.start()

    def stop(self):
        """Stop the background worker thread."""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def queue_event(self, event_dict: dict):
        """
        Thread-safe method to add an event to the outbound queue.
        If the queue is full (e.g. server down for a long time), oldest events drop.
        """
        if not self.enabled:
            return
        
        try:
            # If full, remove oldest to make room
            if self.queue.full():
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    pass
            self.queue.put_nowait(event_dict)
        except queue.Full:
            pass # Shouldn't happen due to above, but safe

    def _connect(self):
        """Attempt to connect to the central server."""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((self.host, self.port))
            # Switch to blocking mode for stable transmission, but keep a timeout to detect dead connections
            s.settimeout(10.0) 
            self._socket = s
            return True
        except (socket.error, socket.timeout):
            return False

    def _worker_loop(self):
        """Background thread pulling events from the queue and sending them."""
        connected = False

        while self._running:
            # Connect if needed
            if not connected:
                connected = self._connect()
                if not connected:
                    # Wait before reconnecting to prevent CPU spinning
                    time.sleep(self.reconnect_interval)
                    continue

            # We are connected, process the queue
            try:
                # Block for a short time so we can check self._running periodically
                event_dict = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # Serialize event
            try:
                payload = json.dumps(event_dict) + "\n"
                payload_bytes = payload.encode('utf-8')
            except TypeError:
                # Event is not JSON serializable, drop it
                self.queue.task_done()
                continue

            # Attempt to send
            try:
                self._socket.sendall(payload_bytes)
                self.queue.task_done()
            except (socket.error, socket.timeout, BrokenPipeError):
                # Connection dropped. Re-queue the event at the front (LIFO-ish to prevent loss)
                # queue.Queue doesn't have put_front, so we'll just put it back. 
                # (Order is less important than preservation here)
                try:
                    if not self.queue.full():
                        self.queue.put(event_dict)
                except queue.Full:
                    pass
                
                connected = False
                # The loop will retry connection on the next iteration
