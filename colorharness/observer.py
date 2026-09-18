"""Observer: read-only factual collection, separated from interpretation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Optional

from ._common import now_utc_iso

OBSERVATION_TYPES: frozenset[str] = frozenset(
    {"logs", "metrics", "health", "ci", "dependency", "repo_state", "changes"}
)

FORBIDDEN_INTERPRETATION_KEYS: frozenset[str] = frozenset(
    {"interpretation", "assessment", "conclusion", "recommendation"}
)


class ObserverError(Exception):
    pass


class ObservationTypeError(ObserverError):
    pass


class InterpretationInObservationError(ObserverError):
    pass


@dataclass(frozen=True)
class Observation:
    """A collected fact. Facts and interpretations are stored separately."""

    observation_id: str
    task_id: str
    observation_type: str
    detail: dict
    source: str
    timestamp: str
    correlation_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.observation_type not in OBSERVATION_TYPES:
            raise ObservationTypeError(
                f"unknown observation_type '{self.observation_type}'; "
                f"allowed: {sorted(OBSERVATION_TYPES)}"
            )
        if not self.detail:
            raise ObserverError("an observation requires non-empty detail")
        forbidden = set(self.detail) & FORBIDDEN_INTERPRETATION_KEYS
        if forbidden:
            raise InterpretationInObservationError(
                f"observations carry facts, never interpretation; "
                f"forbidden keys in detail: {sorted(forbidden)}"
            )

    def payload(self) -> dict[str, Any]:
        return {"observation_type": self.observation_type, "detail": dict(self.detail)}


class Observer:
    """Collects facts without writing any durable state.

    The observer holds no ledger handle and no storage path: collecting
    returns an :class:`Observation` value; persisting it as evidence is the
    white team's governed act (``WhiteTeam.record_observations``).
    """

    def __init__(self, observer_id: str = "observer.ro-1"):
        self.observer_id = observer_id

    def collect(
        self,
        *,
        task_id: str,
        observation_type: str,
        detail: dict,
        source: str = "observer://collect",
        correlation_id: Optional[str] = None,
    ) -> Observation:
        return Observation(
            observation_id=f"obs-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            observation_type=observation_type,
            detail=dict(detail),
            source=source,
            timestamp=now_utc_iso(),
            correlation_id=correlation_id,
        )