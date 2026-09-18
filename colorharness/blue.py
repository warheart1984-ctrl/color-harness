"""Blue Team: defense and operations — monitoring, alerts, recommended actions.

Blue consumes factual observations and produces *interpretations* (alerts and
recommendations). Interpretations are kept separate from the facts they cite;
every recommendation and alert carries the evidence references it is based on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional

from ._common import now_utc_iso
from .observer import Observation


class BlueTeamError(Exception):
    pass


class NoEvidenceError(BlueTeamError):
    pass


class UnauthorizedActorError(BlueTeamError):
    pass


class AlertConditionError(BlueTeamError):
    pass


@dataclass(frozen=True)
class Recommendation:
    recommendation_id: str
    task_id: str
    actor: str
    recommended_action: str
    rationale: str
    severity: str
    evidence_refs: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise NoEvidenceError(
                "a recommendation must cite the evidence it is based on"
            )
        if not self.recommended_action.strip():
            raise BlueTeamError("a recommendation needs a recommended action")


@dataclass(frozen=True)
class Alert:
    alert_id: str
    task_id: str
    metric: str
    observed_value: float
    threshold: float
    severity: str
    observation_refs: tuple[str, ...]
    timestamp: str


@dataclass(frozen=True)
class RunbookEntry:
    """A proposed, attributable runbook step. Proposals are never writes."""

    entry_id: str
    task_id: str
    actor: str
    procedure: str
    source_refs: tuple[str, ...]
    severity: str
    timestamp: str

    def __post_init__(self) -> None:
        if not self.source_refs:
            raise NoEvidenceError(
                "a runbook entry must cite the evidence it is based on"
            )


class BlueTeam:
    BLUE_ID = "blue.obs-1"

    def __init__(self, registry=None):
        self.registry = registry

    def _check_actor(self, actor: str) -> None:
        if self.registry is None:
            return
        if not self.registry.is_registered(actor):
            raise UnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "blue":
            raise UnauthorizedActorError(
                f"actor '{actor}' is not a blue team agent"
            )

    def recommend(
        self,
        task_id: str,
        *,
        actor: str,
        recommended_action: str,
        rationale: str,
        evidence_refs: tuple[str, ...],
        severity: str = "warning",
    ) -> Recommendation:
        self._check_actor(actor)
        if not evidence_refs:
            raise NoEvidenceError(
                "a recommendation must cite the evidence it is based on"
            )
        return Recommendation(
            recommendation_id=f"rec-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            recommended_action=recommended_action,
            rationale=rationale,
            severity=severity,
            evidence_refs=tuple(evidence_refs),
            timestamp=now_utc_iso(),
        )

    def eligibility(self, task_id: str, observations: tuple[Observation, ...]) -> bool:
        """Facts-only guard: observations may carry no interpretation."""
        return all(
            not set(obs.detail) & {"interpretation", "assessment", "conclusion", "recommendation"}
            for obs in observations
        )

    def monitor(
        self,
        *,
        task_id: str,
        observations: tuple[Observation, ...],
        thresholds: dict[str, tuple[float, float]],
    ) -> list[Alert]:
        """Threshold check. thresholds: {metric: (warning_at, critical_at)}.

        Only *facts* fire alerts; each alert cites its source observation.
        """
        alerts: list[Alert] = []
        for obs in observations:
            if obs.observation_type != "metrics":
                continue
            metric = obs.detail.get("metric")
            value = obs.detail.get("value")
            if isinstance(value, (int, float)):
                value = float(value)
            if not isinstance(metric, str) or not isinstance(value, float):
                continue
            spec = thresholds.get(metric)
            if spec is None:
                continue
            warning_at, critical_at = spec
            if value >= critical_at:
                severity = "critical"
                level = critical_at
            elif value >= warning_at:
                severity = "warning"
                level = warning_at
            else:
                continue
            alerts.append(
                Alert(
                    alert_id=f"alt-{uuid.uuid4().hex[:12]}",
                    task_id=task_id,
                    metric=metric,
                    observed_value=value,
                    threshold=level,
                    severity=severity,
                    observation_refs=(obs.observation_id,),
                    timestamp=now_utc_iso(),
                )
            )
        return alerts

    def draft_runbook(
        self,
        *,
        task_id: str,
        actor: str,
        procedure: str,
        source_refs: tuple[str, ...],
        severity: str = "warning",
    ) -> RunbookEntry:
        self._check_actor(actor)
        if not source_refs:
            raise NoEvidenceError(
                "a runbook entry must cite the evidence it is based on"
            )
        return RunbookEntry(
            entry_id=f"run-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            procedure=procedure,
            source_refs=tuple(source_refs),
            severity=severity,
            timestamp=now_utc_iso(),
        )