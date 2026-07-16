"""
Base class for all CredHunt protocol scanner plugins.

Every plugin implements scan(target, port, timeout) and returns a list of
Finding dicts. This is the contract the orchestrator relies on -- adding a
new protocol means writing one new file in plugins/ and registering it,
without touching orchestrator.py or any other plugin.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Finding:
    target: str
    port: int
    protocol: str
    finding_type: str          # e.g. "banner", "credential_pattern", "aws_key"
    raw_value: str             # the actual matched string (never leaves this process unhashed)
    context: str = ""          # surrounding text, for entropy/whitelist checks
    severity: str = "info"     # info | low | medium | high | critical
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    plugin: str = ""


class ScannerPlugin(ABC):
    """Every protocol plugin (HTTP, FTP, SMTP, SSH, ...) subclasses this."""

    name: str = "base"
    default_port: int = 0

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    @abstractmethod
    def scan(self, target: str, port: Optional[int] = None) -> list[Finding]:
        """
        Connect to `target` on `port` (or self.default_port), grab whatever
        the protocol exposes (banner / headers / response body), and return
        a list of Finding objects. Must NOT attempt authentication, brute
        force, or any action beyond passive connection + read. Must raise
        no unhandled exceptions -- connection failures should be caught and
        returned as an empty list (a dead/closed port is a normal result,
        not an error).
        """
        raise NotImplementedError
