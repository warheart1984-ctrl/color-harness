"""Green Team: deployment plans, approved releases, and rollback operations.

Green plans releases with a built-in rollback plan (never flawed without one),
executes a release only with recorded approval, and records releases and
rollbacks as `release` / `rollback` evidence via the white team
(``WhiteTeam.record_green_output``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from ._common import now_utc_iso


class GreenTeamError(Exception):
    pass


class GreenUnauthorizedActorError(GreenTeamError):
    pass


class GreenRollbackPlanRequired(GreenTeamError):
    pass


class GreenReleaseNotApproved(GreenTeamError):
    pass


class InvalidReleasePlanError(GreenTeamError):
    pass


class InvalidRollbackError(GreenTeamError):
    pass


@dataclass(frozen=True)
class ReleasePlan:
    """A deployment plan that always carries its rollback plan."""

    plan_id: str
    task_id: str
    actor: str
    title: str
    artifact_ref: str
    target_environment: str
    phases: tuple[str, ...]
    verification_refs: tuple[str, ...]
    rollback_metadata: dict
    timestamp: str

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise InvalidReleasePlanError("a release plan needs a title")
        if not self.artifact_ref.strip():
            raise InvalidReleasePlanError("a release plan needs an artifact ref")
        if not self.target_environment.strip():
            raise InvalidReleasePlanError("a release plan needs a target environment")
        if not self.phases:
            raise InvalidReleasePlanError("a release plan needs rollout phases")
        if not self.rollback_metadata or not any(
            str(v).strip() for v in self.rollback_metadata.values()
        ):
            raise GreenRollbackPlanRequired(
                "green cannot plan a release without a rollback plan"
            )


@dataclass(frozen=True)
class Release:
    """An executed release, citable in `release` evidence."""

    release_id: str
    task_id: str
    actor: str
    artifact_ref: str
    target_environment: str
    plan_ref: str
    approval_refs: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        if not self.artifact_ref.strip():
            raise InvalidReleasePlanError("a release needs an artifact ref")
        if not self.target_environment.strip():
            raise InvalidReleasePlanError("a release needs a target environment")
        if not self.approval_refs:
            raise GreenReleaseNotApproved(
                "green cannot execute a release with no recorded approval"
            )


@dataclass(frozen=True)
class Rollback:
    """A recorded rollback action tied to a release."""

    rollback_id: str
    task_id: str
    actor: str
    release_ref: str
    steps: tuple[str, ...]
    reason: str
    timestamp: str

    def __post_init__(self) -> None:
        if not self.release_ref.strip():
            raise InvalidRollbackError("a rollback must reference its release")
        if not self.steps:
            raise InvalidRollbackError("a rollback needs steps to execute")
        if not self.reason.strip():
            raise InvalidRollbackError("a rollback needs a reason")


class GreenTeam:
    GREEN_ID = "green.rel-1"

    def __init__(self, registry=None, governance=None):
        self.registry = registry
        self.governance = governance

    def _check_actor(self, actor: str) -> None:
        if self.registry is None or not self.registry.is_registered(actor):
            raise GreenUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "green":
            raise GreenUnauthorizedActorError(
                f"actor '{actor}' is not a green team agent"
            )

    def release_plan(
        self,
        task_id: str,
        *,
        actor: str,
        title: str,
        artifact_ref: str,
        target_environment: str,
        phases: tuple[str, ...],
        verification_refs: tuple[str, ...] = (),
        rollback_metadata: dict,
    ) -> ReleasePlan:
        self._check_actor(actor)
        return ReleasePlan(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            title=title,
            artifact_ref=artifact_ref,
            target_environment=target_environment,
            phases=tuple(phases),
            verification_refs=tuple(verification_refs),
            rollback_metadata=dict(rollback_metadata),
            timestamp=now_utc_iso(),
        )

    def execute_release(
        self,
        task_id: str,
        *,
        actor: str,
        plan: Optional[ReleasePlan],
        approvals: tuple[str, ...],
    ) -> Release:
        self._check_actor(actor)
        if plan is None:
            raise InvalidReleasePlanError(
                "green cannot execute a release without a release plan"
            )
        if self.governance is None:
            raise GreenReleaseNotApproved("green requires White governance to execute releases")
        if self.governance.is_paused(task_id):
            raise GreenReleaseNotApproved("green cannot release while White has paused the task")
        valid = set(self.governance.valid_approval_refs(task_id, "release"))
        quorum = self.governance.approval_quorum_met(task_id, "release")
        if not quorum or not approvals or not set(approvals) <= valid:
            raise GreenReleaseNotApproved(
                "green cannot execute a release without recorded approval "
                "for the release action"
            )
        return Release(
            release_id=f"rel-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            artifact_ref=plan.artifact_ref,
            target_environment=plan.target_environment,
            plan_ref=plan.plan_id,
            approval_refs=tuple(approvals),
            timestamp=now_utc_iso(),
        )

    def rollback(
        self,
        task_id: str,
        *,
        actor: str,
        release_ref: str,
        steps: tuple[str, ...],
        reason: str = "",
    ) -> Rollback:
        self._check_actor(actor)
        return Rollback(
            rollback_id=f"rb-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            release_ref=release_ref,
            steps=tuple(steps),
            reason=reason or "rollout degraded within the approved window",
            timestamp=now_utc_iso(),
        )
