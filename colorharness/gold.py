"""Gold Team: versioned standards, reference pipelines, policy-as-code, and
reliability direction. Exceptions require documented approval and expiry.

Gold authors versioned standards (strictly-increasing versions within an
instance) and reference pipelines, and may grant scoped exceptions to a
standard only with a recorded approval and a finite expiry — unbounded
exceptions are refused. Standards, pipelines, and exceptions are persisted as
`standard` / `pipeline` / `exception` evidence by the white team
(``WhiteTeam.record_gold_output``).
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ._common import now_utc_iso
from .secrets import raise_if_secret

if TYPE_CHECKING:
    from .governance import WhiteTeam

VERSION_RE = re.compile(r"^\d+\.\d+$")


class GoldTeamError(Exception):
    pass


class GoldUnauthorizedActorError(GoldTeamError):
    pass


class InvalidStandardError(GoldTeamError):
    pass


class VersionConflictError(GoldTeamError):
    pass


class ExceptionRequiresApproval(GoldTeamError):
    pass


class UnboundedExceptionRefusedError(GoldTeamError):
    pass


class InvalidExceptionError(GoldTeamError):
    pass


@dataclass(frozen=True)
class Standard:
    """A versioned standard or policy-as-code rule set."""

    standard_id: str
    title: str
    version: str
    domain: str
    policies: tuple[str, ...]
    rationale: str
    supersedes: Optional[str]
    refs: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        if not self.standard_id.strip():
            raise InvalidStandardError("a standard needs an id")
        if not self.title.strip():
            raise InvalidStandardError("a standard needs a title")
        if not VERSION_RE.match(self.version or ""):
            raise InvalidStandardError(
                "standard version must be dotted numbers (e.g. '1.0')"
            )
        if not self.domain.strip():
            raise InvalidStandardError("a standard needs a domain")
        if not self.policies:
            raise InvalidStandardError(
                "policy-as-code needs at least one policy rule"
            )
        if not self.rationale.strip():
            raise InvalidStandardError("a standard needs a rationale")


@dataclass(frozen=True)
class ReferencePipeline:
    """A versioned reference pipeline for CI/CD or reliability direction."""

    pipeline_id: str
    title: str
    version: str
    stages: tuple[str, ...]
    triggers: tuple[str, ...]
    refs: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        if not self.pipeline_id.strip():
            raise InvalidStandardError("a pipeline needs an id")
        if not self.title.strip():
            raise InvalidStandardError("a pipeline needs a title")
        if not VERSION_RE.match(self.version or ""):
            raise InvalidStandardError(
                "pipeline version must be dotted numbers (e.g. '1.0')"
            )
        if not self.stages:
            raise InvalidStandardError("a reference pipeline needs stages")
        if not self.triggers:
            raise InvalidStandardError("a reference pipeline needs triggers")


@dataclass(frozen=True)
class ExceptionGrant:
    """A scoped, expiring exception to a standard, backed by recorded approval."""

    exception_id: str
    task_id: str
    actor: str
    standard_ref: str
    approver: str
    approval_ref: str
    scope: str
    expiry_epoch: int
    reason: str
    timestamp: str

    def __post_init__(self) -> None:
        if not self.standard_ref.strip():
            raise InvalidExceptionError(
                "an exception must reference its standard"
            )
        if not self.approver.strip():
            raise InvalidExceptionError("an exception needs an approver")
        if not self.approval_ref.strip():
            raise ExceptionRequiresApproval(
                "gold cannot make an exception it does not approve"
            )
        if not self.scope.strip():
            raise InvalidExceptionError("an exception needs a scope")
        if not self.reason.strip():
            raise InvalidExceptionError("an exception needs a reason")
        if self.expiry_epoch is None or int(self.expiry_epoch) <= int(time.time()):
            raise UnboundedExceptionRefusedError(
                "gold refuses unbounded exceptions; set an expiry in the future"
            )


class GoldTeam:
    GOLD_ID = "gold.plan-1"

    def __init__(self, registry=None, governance: Optional["WhiteTeam"] = None):
        self.registry = registry
        self.governance = governance
        self._standards: dict[str, dict[str, Standard]] = {}
        self._pipelines: dict[str, dict[str, ReferencePipeline]] = {}

    def _check_actor(self, actor: str) -> None:
        if self.registry is None or not self.registry.is_registered(actor):
            raise GoldUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "gold":
            raise GoldUnauthorizedActorError(
                f"actor '{actor}' is not a gold team agent"
            )

    @staticmethod
    def _bump_check(group: dict, obj_id: str, version: str) -> None:
        versions = group.get(obj_id, {})
        if version in versions:
            raise VersionConflictError(
                f"'{obj_id}' version {version} is already authored"
            )
        highest = version
        for existing in versions:
            if existing >= highest:
                raise VersionConflictError(
                    f"'{obj_id}' already has version {existing}; new versions "
                    "must be strictly higher"
                )

    def author_standard(
        self,
        *,
        actor: str,
        standard_id: str,
        title: str,
        version: str,
        domain: str,
        policies: tuple[str, ...],
        rationale: str,
        supersedes: Optional[str] = None,
        refs: tuple[str, ...] = (),
    ) -> Standard:
        self._check_actor(actor)
        self._bump_check(self._standards, standard_id, version)
        standards = self._standards.setdefault(standard_id, {})
        standard = Standard(
            standard_id=standard_id,
            title=title,
            version=version,
            domain=domain,
            policies=tuple(policies),
            rationale=rationale,
            supersedes=supersedes,
            refs=tuple(refs),
            timestamp=now_utc_iso(),
        )
        raise_if_secret(standard.policies)
        standards[version] = standard
        return standard

    def define_pipeline(
        self,
        *,
        actor: str,
        pipeline_id: str,
        title: str,
        version: str,
        stages: tuple[str, ...],
        triggers: tuple[str, ...],
        refs: tuple[str, ...] = (),
    ) -> ReferencePipeline:
        self._check_actor(actor)
        self._bump_check(self._pipelines, pipeline_id, version)
        pipelines = self._pipelines.setdefault(pipeline_id, {})
        pipeline = ReferencePipeline(
            pipeline_id=pipeline_id,
            title=title,
            version=version,
            stages=tuple(stages),
            triggers=tuple(triggers),
            refs=tuple(refs),
            timestamp=now_utc_iso(),
        )
        raise_if_secret(pipeline.stages)
        pipelines[version] = pipeline
        return pipeline

    def grant_exception(
        self,
        task_id: str,
        *,
        actor: str,
        standard_ref: str,
        approver: str,
        approval_ref: str,
        scope: str,
        expiry_epoch: int,
        reason: str,
    ) -> ExceptionGrant:
        self._check_actor(actor)
        grant = ExceptionGrant(
            exception_id=f"exc-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            standard_ref=standard_ref,
            approver=approver,
            approval_ref=approval_ref,
            scope=scope,
            expiry_epoch=int(expiry_epoch),
            reason=reason,
            timestamp=now_utc_iso(),
        )
        if self.governance is None or self.governance.registry is not self.registry:
            raise ExceptionRequiresApproval(
                "gold exceptions require the shared White approval ledger"
            )
        approval = next(
            (
                approval
                for approval in self.governance.approvals_for(task_id)
                if approval_ref in {approval.approval_id, approval.evidence_id}
            ),
            None,
        )
        if approval is None or not self.governance.approval_valid(
            approval.approval_id, task_id, "policy_exception"
        ):
            raise ExceptionRequiresApproval(
                "exception approval must resolve to a live White policy_exception approval"
            )
        if approval.approver == actor:
            raise InvalidExceptionError("an exception author cannot approve their own exception")
        if approval.approver_role != approver or approver not in {
            "security-lead", "platform-owner"
        }:
            raise ExceptionRequiresApproval(
                "exception approval must come from the named reviewer role"
            )
        return grant
