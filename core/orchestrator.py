"""
Orchestrator: dispatches (target, plugin) scan jobs across a bounded thread
pool, applies rate limiting (safe mode), validates raw findings, and streams
progress to the console line-by-line as results complete.

This is the piece that turns "a scanner" into "a concurrent scanner" --
network I/O is the bottleneck (waiting on connect/response), so a thread
pool lets many targets be in-flight at once instead of scanning serially.
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from core.validator import validate
from core.evidence_store import EvidenceStore


class Orchestrator:
    def __init__(self, plugins: dict, max_workers: int = 10,
                 safe_mode: bool = True, requests_per_second: float = 5.0):
        """
        plugins: {"http": HTTPPlugin(), "ftp": FTPPlugin(), ...}
        safe_mode: if True, enforces a global rate limit across all workers
                   so scanning many targets can't hammer a single service.
        """
        self.plugins = plugins
        self.max_workers = max_workers
        self.safe_mode = safe_mode
        self.evidence = EvidenceStore()

        # Simple global token-bucket-style rate limiter shared by all threads.
        self._lock = threading.Lock()
        self._min_interval = (1.0 / requests_per_second) if safe_mode else 0
        self._last_call = 0.0

    def _throttle(self):
        if not self.safe_mode:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def _run_one_job(self, target, port, protocol_name):
        self._throttle()
        plugin = self.plugins[protocol_name]
        raw_findings = plugin.scan(target, port)

        validated = []
        for f in raw_findings:
            ok, reason = validate(f.finding_type, f.raw_value)
            if ok or f.finding_type == "banner":  # banners are informational, always kept
                validated.append((f, reason))
        return target, protocol_name, validated

    def run(self, targets: list[str], protocols: list[str] = None, ports: dict = None):
        """
        targets: list of hosts/IPs
        protocols: which plugins to run against every target (defaults to all loaded)
        ports: optional {"http": 8080} override of default ports
        Streams a line to stdout as each job completes, returns total finding count.
        """
        protocols = protocols or list(self.plugins.keys())
        ports = ports or {}
        jobs = [(t, ports.get(p), p) for t in targets for p in protocols]

        total_findings = 0
        print(f"[orchestrator] dispatching {len(jobs)} jobs across {self.max_workers} workers "
              f"(safe_mode={self.safe_mode})")

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._run_one_job, t, p, proto): (t, proto) for t, p, proto in jobs}
            for future in as_completed(futures):
                target, protocol_name = futures[future]
                try:
                    target, protocol_name, validated = future.result()
                except Exception as e:
                    print(f"[{protocol_name}] {target} -> error: {e}")
                    continue

                if not validated:
                    print(f"[{protocol_name}] {target} -> no findings")
                    continue

                for finding, reason in validated:
                    self.evidence.store(finding)
                    total_findings += 1
                    print(f"[{protocol_name}] {target}:{finding.port} -> "
                          f"{finding.finding_type} ({finding.severity}) -- {reason}")

        print(f"[orchestrator] scan complete. {total_findings} findings stored.")
        return total_findings
