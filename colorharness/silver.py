"""Silver Team: implementation — change manifests with rollback metadata.

Silver prepares changes in isolated branches or worktrees. A ``ChangeManifest``
lists every file, branch, resource, and configuration an implementation touches,
plus its diff summary, its task ID and approval scope, and the evidence
(plan/diagnosis) it implements. Silver never merges and never deploys; its
output is persisted as ``change`` evidence by the white team
(``WhiteTeam.record_silver_output``). Secrets never appear in an implementation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from ._common import now_utc_iso
from .secrets import scan_for_secrets

SILVER_CHANGE_TYPES: frozenset[str] = frozenset({"branch", "config"})


class SilverTeamError(Exception):
    pass


class SilverNoEvidenceError(SilverTeamError):
    pass


class SilverUnauthorizedActorError(SilverTeamError):
    pass


class InvalidImplementationError(SilverTeamError):
    pass


class SecretInImplementationError(SilverTeamError):
    pass


@dataclass(frozen=True)
class ChangeManifest:
    """The attributable record of one implementation touchpoint set."""

    manifest_id: str
    task_id: str
    actor: str
    change_type: str
    branch: str
    files: tuple[str, ...]
    diff_summary: str
    resources: tuple[str, ...]
    configurations: tuple[str, ...]
    approval_scope: dict
    plan_refs: tuple[str, ...]
    rollback_metadata: dict
    timestamp: str

    def __post_init__(self) -> None:
        if self.change_type not in SILVER_CHANGE_TYPES:
            raise InvalidImplementationError(
                f"change_type must be one of {sorted(SILVER_CHANGE_TYPES)}"
            )
        if not self.branch.strip():
            raise InvalidImplementationError(
                "an implementation needs an isolated branch or worktree"
            )
        if not self.files:
            raise InvalidImplementationError(
                "an implementation must list the files it touches"
            )
        if not self.diff_summary.strip():
            raise InvalidImplementationError(
                "an implementation needs a diff summary"
            )
        if not self.plan_refs:
            raise SilverNoEvidenceError(
                "an implementation must cite the plan evidence it implements"
            )
        if not self.rollback_metadata:
            raise InvalidImplementationError(
                "an implementation needs rollback metadata"
            )
        kinds = scan_for_secrets(
            {
                "branch": self.branch,
                "files": self.files,
                "diff_summary": self.diff_summary,
                "rollback_metadata": self.rollback_metadata,
            }
        )
        if kinds:
            raise SecretInImplementationError(
                f"implementation carries secret material: {', '.join(kinds)}"
            )


class SilverTeam:
    SILVER_ID = "silver.build-1"

    def __init__(self, registry=None):
        self.registry = registry

    def _check_actor(self, actor: str) -> None:
        if self.registry is None or not self.registry.is_registered(actor):
            raise SilverUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "silver":
            raise SilverUnauthorizedActorError(
                f"actor '{actor}' is not a silver team agent"
            )

    def present_change(
        self,
        task_id: str,
        *,
        actor: str,
        change_type: str,
        branch: str,
        files: tuple[str, ...],
        diff_summary: str,
        plan_refs: tuple[str, ...],
        rollback_metadata: dict,
        resources: tuple[str, ...] = (),
        configurations: tuple[str, ...] = (),
        approval_scope: Optional[dict] = None,
    ) -> ChangeManifest:
        self._check_actor(actor)
        return ChangeManifest(
            manifest_id=f"chg-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            change_type=change_type,
            branch=branch,
            files=tuple(files),
            diff_summary=diff_summary,
            resources=tuple(resources),
            configurations=tuple(configurations),
            approval_scope=dict(approval_scope or {}),
            plan_refs=tuple(plan_refs),
            rollback_metadata=dict(rollback_metadata),
            timestamp=now_utc_iso(),
        )
