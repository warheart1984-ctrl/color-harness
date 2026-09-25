"""Red Team: authorized adversarial testing — findings with reproduction,
impact, severity, and remediation recommendation.

Red tests failure modes only within explicitly authorized boundaries: it
refuses unspecified targets and refuses destructive tests without recorded
approval, and every finding includes reproduction steps, impact, severity, and
a remediation recommendation. Findings are persisted as `finding` evidence by
the white team (``WhiteTeam.record_red_output``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from ._common import now_utc_iso
from .secrets import raise_if_secret

FINDING_SEVERITIES: frozenset[str] = frozenset(
    {"low", "medium", "high", "critical"}
)


class RedTeamError(Exception):
    pass


class RedUnauthorizedActorError(RedTeamError):
    pass


class RedUnspecifiedTargetError(RedTeamError):
    pass


class RedDestructiveTestRefusedError(RedTeamError):
    pass


class InvalidFindingError(RedTeamError):
    pass


@dataclass(frozen=True)
class Finding:
    """A reproducible observation from authorized adversarial testing."""

    finding_id: str
    task_id: str
    actor: str
    title: str
    reproduction: tuple[str, ...]
    impact: str
    severity: str
    remediation_recommendation: str
    targets: tuple[str, ...]
    techniques: tuple[str, ...]
    destructive: bool
    approval_refs: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        # Findings remain in memory before White persists them. Reject secret
        # material here as well as at the ledger boundary so callers cannot
        # retain or forward an unsafe Finding after persistence is refused.
        raise_if_secret((
            self.finding_id,
            self.task_id,
            self.actor,
            self.title,
            self.reproduction,
            self.impact,
            self.severity,
            self.remediation_recommendation,
            self.targets,
            self.techniques,
            self.approval_refs,
            self.timestamp,
        ))
        if not self.title.strip():
            raise InvalidFindingError("a finding needs a title")
        if not self.reproduction:
            raise InvalidFindingError(
                "a finding with no reproduction is not a finding"
            )
        if not self.impact.strip():
            raise InvalidFindingError("a finding needs an impact statement")
        if self.severity not in FINDING_SEVERITIES:
            raise InvalidFindingError(
                f"severity must be one of {sorted(FINDING_SEVERITIES)}"
            )
        if not self.remediation_recommendation.strip():
            raise InvalidFindingError(
                "a finding needs a remediation recommendation"
            )
        if not self.targets:
            raise RedUnspecifiedTargetError(
                "red team refuses unspecified targets; name the targets tested"
            )
        if self.destructive and not self.approval_refs:
            raise RedDestructiveTestRefusedError(
                "red team refuses destructive tests without recorded approval"
            )


class RedTeam:
    RED_ID = "red.tar-1"

    def __init__(self, registry=None):
        self.registry = registry

    def _check_actor(self, actor: str) -> None:
        if self.registry is None or not self.registry.is_registered(actor):
            raise RedUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "red":
            raise RedUnauthorizedActorError(
                f"actor '{actor}' is not a red team agent"
            )

    def report_finding(
        self,
        task_id: str,
        *,
        actor: str,
        title: str,
        reproduction: tuple[str, ...],
        impact: str,
        severity: str,
        remediation_recommendation: str,
        targets: tuple[str, ...],
        techniques: tuple[str, ...] = (),
        destructive: bool = False,
        approval_refs: tuple[str, ...] = (),
    ) -> Finding:
        self._check_actor(actor)
        return Finding(
            finding_id=f"find-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            title=title,
            reproduction=tuple(reproduction),
            impact=impact,
            severity=severity,
            remediation_recommendation=remediation_recommendation,
            targets=tuple(targets),
            techniques=tuple(techniques),
            destructive=destructive,
            approval_refs=tuple(approval_refs),
            timestamp=now_utc_iso(),
        )
