"""Durable, append-only structured event log with idempotent request replay.

Idempotency model: a replayed message with the same ``(actor, request_id)``
key returns the cached outcome. The key fingerprints the **payload** (task
operation fields), never the envelope; reusing a key with a different payload
is an ``IDEMPOTENCY_CONFLICT``.
"""

from __future__ import annotations

import json
import os
import dataclasses
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from ._common import now_utc_iso
from .ledger import canonical_json, sha256_hex
from .secrets import raise_if_secret

GENESIS_HASH = "0" * 64


class CorruptEventStoreError(Exception):
    pass


class _ConflictMarker:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostic helper
        return "IDEMPOTENCY_CONFLICT"


# Sentinel returned by EventLog.seen() when a key is reused with a different
# payload.
IDEMPOTENCY_CONFLICT = _ConflictMarker()


def idempotency_fingerprint(*parts: Any) -> str:
    """sha256 of the JCS payload parts that identify an operation's intent."""
    return sha256_hex(canonical_json(list(parts)))


@dataclass(frozen=True)
class Event:
    event_id: str
    task_id: str
    correlation_id: str
    seq: int
    request_id: str
    trigger: str
    actor: str
    timestamp: str
    reason: str
    outcome: str
    from_state: str | None
    to_state: str | None
    resume_state: str | None = None
    error_code: str | None = None
    decision_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
    payload: dict[str, Any] = field(default_factory=dict)
    payload_fingerprint: str = ""
    prev_hash: str = GENESIS_HASH
    content_hash: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evidence_refs"] = list(self.evidence_refs)
        return data

    def body_hash(self) -> str:
        body = self.to_dict()
        body.pop("content_hash", None)
        return sha256_hex(canonical_json(body))

    @classmethod
    def from_dict(cls, data: dict) -> "Event":
        return cls(
            event_id=data["event_id"],
            task_id=data["task_id"],
            correlation_id=data["correlation_id"],
            seq=int(data["seq"]),
            request_id=data["request_id"],
            trigger=data["trigger"],
            actor=data["actor"],
            timestamp=data["timestamp"],
            reason=data["reason"],
            outcome=data["outcome"],
            from_state=data.get("from_state"),
            to_state=data.get("to_state"),
            resume_state=data.get("resume_state"),
            error_code=data.get("error_code"),
            decision_id=data.get("decision_id"),
            evidence_refs=tuple(data.get("evidence_refs") or ()),
            payload=data.get("payload") or {},
            payload_fingerprint=data.get("payload_fingerprint", ""),
            prev_hash=data.get("prev_hash", GENESIS_HASH),
            content_hash=data.get("content_hash", ""),
        )


class EventLog:
    def __init__(self, path: str | None = None):
        self.path = path
        self.events: list[Event] = []
        self._seen: dict[tuple[str, str], tuple[str, dict]] = {}
        if path:
            self._load(path)

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        previous = GENESIS_HASH
        for index, line in enumerate(lines):
            line = line.strip()
            if not line:
                raise CorruptEventStoreError(
                    f"corrupt blank event line {index + 1} in {path}"
                )
            try:
                event = Event.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError):
                raise CorruptEventStoreError(
                    f"corrupt event line {index + 1} in {path}: {line[:80]!r}"
                )
            if event.prev_hash != previous or not event.content_hash:
                raise CorruptEventStoreError(f"event hash chain mismatch at line {index + 1}")
            if event.body_hash() != event.content_hash:
                raise CorruptEventStoreError(f"event content hash mismatch at line {index + 1}")
            previous = event.content_hash
            self.events.append(event)
            self._remember(event)

    def _remember(self, event: Event) -> None:
        """Record the outcome under its (actor, request_id) idempotency key."""
        self._seen[(event.actor, event.request_id)] = (
            event.payload_fingerprint,
            self._result_for(event),
        )

    def _write(self, event: Event, result: dict) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            fh.flush()

    @staticmethod
    def _result_for(event: Event) -> dict:
        result = {
            "request_id": event.request_id,
            "task_id": event.task_id,
            "success": event.outcome == "SUCCESS",
            "event": event.to_dict(),
        }
        if event.outcome == "REJECTED":
            result["error"] = {
                "code": event.error_code,
                "detail": event.reason,
            }
        return result

    def seen(self, actor: str, request_id: str, fingerprint: str) -> dict | _ConflictMarker | None:
        """Cached outcome for (actor, request_id); None if unseen.

        A key reuse with a *different payload fingerprint* returns
        ``IDEMPOTENCY_CONFLICT`` instead of the cached outcome.
        """
        entry = self._seen.get((actor, request_id))
        if entry is None:
            return None
        stored_fp, result = entry
        if fingerprint and stored_fp and fingerprint != stored_fp:
            return IDEMPOTENCY_CONFLICT
        return result

    def append(self, event: Event, fingerprint: str = "") -> dict:
        raise_if_secret(event.to_dict())
        if not self.verify_chain():
            raise CorruptEventStoreError("event log hash chain is corrupt")
        key = (event.actor, event.request_id)
        existing = self._seen.get(key)
        if existing is not None:
            stored_fp, cached = existing
            if fingerprint and stored_fp and fingerprint != stored_fp:
                return {
                    "request_id": event.request_id,
                    "task_id": event.task_id,
                    "success": False,
                    "event": None,
                    "error": {
                        "code": "IDEMPOTENCY_CONFLICT",
                        "detail": "idempotency key reused with a different payload",
                    },
                }
            return cached
        if fingerprint:
            event = dataclasses.replace(event, payload_fingerprint=fingerprint)
        previous = self.events[-1].content_hash if self.events else GENESIS_HASH
        event = dataclasses.replace(event, prev_hash=previous, content_hash="")
        event = dataclasses.replace(event, content_hash=event.body_hash())
        result = self._result_for(event)
        self.events.append(event)
        self._remember(event)
        self._write(event, result)
        return result

    def __len__(self) -> int:
        return len(self.events)

    def verify_chain(self) -> bool:
        previous = GENESIS_HASH
        for event in self.events:
            if event.prev_hash != previous or event.body_hash() != event.content_hash:
                return False
            previous = event.content_hash
        return True
