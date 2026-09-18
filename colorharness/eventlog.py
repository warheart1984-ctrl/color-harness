"""Durable, append-only structured event log with idempotent request replay."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from ._common import now_utc_iso


class CorruptEventStoreError(Exception):
    pass


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

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evidence_refs"] = list(self.evidence_refs)
        return data

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
        )


class EventLog:
    def __init__(self, path: str | None = None):
        self.path = path
        self.events: list[Event] = []
        self._seen: dict[tuple[str, str], dict] = {}
        if path:
            self._load(path)

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for index, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                event = Event.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError):
                if index == len(lines) - 1:
                    continue
                raise CorruptEventStoreError(
                    f"corrupt event line {index + 1} in {path}: {line[:80]!r}"
                )
            self.events.append(event)
            self._seen[(event.task_id, event.request_id)] = self._result_for(event)

    def _write(self, event: Event, result: dict) -> None:
        self._seen[(event.task_id, event.request_id)] = result
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

    def seen(self, task_id: str, request_id: str) -> dict | None:
        return self._seen.get((task_id, request_id))

    def append(self, event: Event) -> dict:
        result = self._result_for(event)
        if (event.task_id, event.request_id) in self._seen:
            return self._seen[(event.task_id, event.request_id)]
        self.events.append(event)
        self._write(event, result)
        return result

    def __len__(self) -> int:
        return len(self.events)