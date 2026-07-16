"""
Evidence store: persists validated findings with full metadata (timestamp,
plugin source, severity) so the report generator has a single, queryable
source of truth. Secrets are hashed before storage -- the raw value never
touches disk.
"""

import hashlib
import json
from pathlib import Path


class EvidenceStore:
    def __init__(self):
        self._records = []

    def store(self, finding):
        raw = finding.raw_value
        record = {
            "target": finding.target,
            "port": finding.port,
            "protocol": finding.protocol,
            "type": finding.finding_type,
            "severity": finding.severity,
            "context": finding.context,
            "plugin": finding.plugin,
            "timestamp": finding.timestamp,
            "masked_snippet": self._mask(raw),
            "sha256": hashlib.sha256(raw.encode(errors="ignore")).hexdigest(),
        }
        self._records.append(record)
        return record

    @staticmethod
    def _mask(value: str) -> str:
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "..." + value[-4:]

    def all_records(self):
        return list(self._records)

    def save_json(self, path: str):
        Path(path).write_text(json.dumps(self._records, indent=2))
