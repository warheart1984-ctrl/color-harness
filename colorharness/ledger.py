"""Append-only, hash-chained evidence ledger with completeness enforcement."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Optional

from ._common import now_utc_iso
from .secrets import raise_if_secret

GENESIS_HASH = "0" * 64


class LedgerError(Exception):
    pass


class IncompleteEvidenceError(LedgerError):
    pass


class LedgerImmutableError(LedgerError):
    pass


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


PAYLOAD_REQUIREMENTS: dict[str, frozenset[str]] = {
    "transition": frozenset({"previous_state", "new_state", "trigger", "reason_code"}),
    "observation": frozenset({"observation_type", "detail"}),
    "hypothesis": frozenset({"hypothesis", "confidence", "alternatives", "discriminator"}),
    "experiment": frozenset({"setup", "inputs_ref", "result_ref", "verified"}),
    "diagnosis": frozenset({"diagnosis", "confidence", "evidence_refs", "alternatives"}),
    "test_result": frozenset({"command", "version", "exit_status", "artifacts_ref", "evidence_location"}),
    "finding": frozenset({"reproduction", "impact", "severity", "remediation_recommendation"}),
    "remediation": frozenset({"change_ref", "re_test_ref", "verdict"}),
    "approval": frozenset({"approver", "scope", "expiry", "gated_action", "decision_id"}),
    "decision": frozenset({"decision_type", "decider", "reasoning", "scope"}),
    "block": frozenset({"reason_code", "condition", "evidence_refs"}),
    "release": frozenset({"artifact_ref", "target_environment", "plan_ref", "approval_refs"}),
    "scope_declaration": frozenset({"declared_by", "scope", "risk"}),
    "pause": frozenset({"actor", "reason"}),
}

BASE_REQUIRED = frozenset(
    {"evidence_id", "record_type", "status", "actor", "team", "timestamp", "source", "payload"}
)


def required_payload_keys(record_type: str) -> frozenset[str]:
    return PAYLOAD_REQUIREMENTS.get(record_type, frozenset())


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    record_type: str
    status: str
    actor: str
    team: str
    timestamp: str
    source: str
    payload: dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    correlation_id: Optional[str] = None
    agent_id: Optional[str] = None
    refs: tuple[str, ...] = ()
    retention_days: int = 90
    event_id: str = ""
    payload_digest: str = ""
    prev_hash: str = GENESIS_HASH
    signature: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["refs"] = list(self.refs)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceRecord":
        kw = {k: v for k, v in data.items() if k != "record_hash"}
        kw["refs"] = tuple(data.get("refs") or ())
        return cls(**kw)

    def body_hash(self) -> str:
        body = dict(self.to_dict())
        body.pop("signature", None)
        return sha256_hex(canonical_json(body))


def is_complete(record: EvidenceRecord) -> bool:
    if record.status != "complete":
        return False
    for key in BASE_REQUIRED:
        if not record.to_dict().get(key):
            return False
    if not record.payload:
        return False
    missing = required_payload_keys(record.record_type) - set(record.payload)
    return not missing


class EvidenceLedger:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._records: list[EvidenceRecord] = []
        self._index: dict[str, EvidenceRecord] = {}
        if path:
            self._load(path)

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = EvidenceRecord.from_dict(json.loads(line))
                except (ValueError, TypeError):
                    raise LedgerError(f"corrupt ledger line: {line[:80]!r}")
                self._records.append(record)
                self._index[record.evidence_id] = record

    def _write(self, record: EvidenceRecord) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
            fh.flush()

    @staticmethod
    def _seal(
        record: EvidenceRecord,
        prev_hash: str,
    ) -> EvidenceRecord:
        payload_digest = sha256_hex(canonical_json(record.payload))
        sealed = replace(
            record,
            payload_digest=payload_digest,
            prev_hash=prev_hash,
        )
        return sealed

    @property
    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._index.get(evidence_id)

    def append(
        self,
        record_type: str,
        *,
        status: str = "complete",
        actor: str,
        team: str,
        source: str,
        payload: dict,
        task_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        refs: tuple[str, ...] = (),
        retention_days: int = 90,
        event_id: str = "",
    ) -> EvidenceRecord:
        raise_if_secret(payload)
        raise_if_secret(source)
        prev_hash = self._records[-1].body_hash() if self._records else GENESIS_HASH
        record = EvidenceRecord(
            evidence_id=f"evt-{uuid.uuid4().hex[:16]}",
            record_type=record_type,
            status=status,
            actor=actor,
            team=team,
            timestamp=now_utc_iso(),
            source=source,
            payload=dict(payload),
            task_id=task_id,
            correlation_id=correlation_id,
            agent_id=agent_id,
            refs=tuple(refs),
            retention_days=retention_days,
            event_id=event_id,
        )
        record = self._seal(record, prev_hash)
        if status == "complete" and not is_complete(record):
            raise IncompleteEvidenceError(
                f"record '{record.evidence_id}' is missing mandatory fields "
                f"for type '{record_type}'"
            )
        self._records.append(record)
        self._index[record.evidence_id] = record
        self._write(record)
        return record

    def mark_complete(self, evidence_id: str) -> EvidenceRecord:
        record = self._index.get(evidence_id)
        if record is None:
            raise KeyError(evidence_id)
        if not is_complete(record):
            raise IncompleteEvidenceError(
                f"incomplete evidence record '{evidence_id}' cannot be marked complete "
                "in place (append a superseding record instead)"
            )
        raise LedgerImmutableError(
            f"record '{evidence_id}' is already complete; "
            "the ledger is append-only and never mutates"
        )

    def complete_evidence(
        self,
        evidence_id: str,
        *,
        extra_payload: dict,
        actor: str,
        team: str,
        source: str,
    ) -> EvidenceRecord:
        record = self._index.get(evidence_id)
        if record is None:
            raise KeyError(evidence_id)
        if is_complete(record):
            raise LedgerImmutableError(
                f"record '{evidence_id}' is already complete"
            )
        merged = {**record.payload, **extra_payload}
        return self.append(
            record.record_type,
            status="complete",
            actor=actor,
            team=team,
            source=source,
            payload=merged,
            task_id=record.task_id,
            correlation_id=record.correlation_id,
            agent_id=record.agent_id,
            refs=(record.evidence_id,),
            retention_days=record.retention_days,
            event_id=record.event_id,
        )

    def verify_chain(self) -> bool:
        prev = GENESIS_HASH
        for record in self._records:
            if record.prev_hash != prev:
                return False
            prev = record.body_hash()
        return True

    def manifest(self) -> dict:
        """JCS manifest of the whole ledger: digest + fingerprint per record.

        manifest_digest is the sha256 of the JCS-serialised manifest body,
        anchoring the entire append-only store to one value.
        """
        entries = [
            {
                "evidence_id": r.evidence_id,
                "payload_digest": r.payload_digest,
                "prev_hash": r.prev_hash,
                "body_hash": r.body_hash(),
            }
            for r in self._records
        ]
        body = {"records": entries, "count": len(entries)}
        return {
            "manifest_digest": sha256_hex(canonical_json(body)),
            "entries": entries,
        }

    def manifest_digest(self) -> str:
        return self.manifest()["manifest_digest"]

    def verify_manifest(self, expected: Optional[str] = None) -> bool:
        """Compare the recomputed manifest digest against an anchor.

        ``expected`` is the manifest digest previously persisted elsewhere
        (the external anchor); without it the check is trivially consistent
        with the live ledger so tamper detection requires the anchor.
        """
        current = self.manifest()
        recomputed = sha256_hex(
            canonical_json({"records": current["entries"], "count": len(current["entries"])})
        )
        if expected is None:
            return recomputed == current["manifest_digest"]
        return recomputed == expected