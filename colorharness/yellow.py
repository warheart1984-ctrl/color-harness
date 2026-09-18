"""Yellow Team: verification — tests, lint, policy, security scan, smoke,
readiness. Results carry command, version, exit status, and evidence location.

Yellow runs independently of the implementation team: it cannot approve its own
work and its failed checks block progression. Results are persisted as
`test_result` evidence by the white team
(``WhiteTeam.record_yellow_output``); the coordinator refuses
`VERIFICATION_PASSED` while any recorded result for the task has failed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from ._common import now_utc_iso

CHECK_TYPES: frozenset[str] = frozenset(
    {"test", "lint", "policy", "security", "smoke", "readiness"}
)


class YellowTeamError(Exception):
    pass


class YellowNoEvidenceError(YellowTeamError):
    pass


class YellowUnauthorizedActorError(YellowTeamError):
    pass


class InvalidCheckError(YellowTeamError):
    pass


class SelfApprovalError(YellowTeamError):
    pass


@dataclass(frozen=True)
class VerificationResult:
    """One independent verification run, with its evidence location."""

    result_id: str
    task_id: str
    actor: str
    check_type: str
    command: str
    version: str
    exit_status: int
    artifacts_ref: str
    evidence_location: str
    timestamp: str

    def __post_init__(self) -> None:
        if self.check_type not in CHECK_TYPES:
            raise InvalidCheckError(
                f"check_type must be one of {sorted(CHECK_TYPES)}"
            )
        if not self.command.strip():
            raise InvalidCheckError("a check needs a command")
        if not self.version.strip():
            raise YellowNoEvidenceError("a check must record the version it ran")
        if not isinstance(self.exit_status, int):
            raise InvalidCheckError("exit_status must be an integer")
        if not self.artifacts_ref.strip():
            raise YellowNoEvidenceError("a check must reference its artifacts")
        if not self.evidence_location.strip():
            raise YellowNoEvidenceError(
                "a check must record where its evidence lives"
            )

    @property
    def passed(self) -> bool:
        return self.exit_status == 0


class YellowTeam:
    YELLOW_ID = "yellow.ver-1"

    def __init__(self, registry=None):
        self.registry = registry

    def _check_actor(self, actor: str) -> None:
        if self.registry is None:
            return
        if not self.registry.is_registered(actor):
            raise YellowUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "yellow":
            raise YellowUnauthorizedActorError(
                f"actor '{actor}' is not a yellow team agent"
            )

    def run_check(
        self,
        task_id: str,
        *,
        actor: str,
        check_type: str,
        command: str,
        version: str,
        exit_status: int,
        artifacts_ref: str,
        evidence_location: str,
    ) -> VerificationResult:
        self._check_actor(actor)
        return VerificationResult(
            result_id=f"res-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            check_type=check_type,
            command=command,
            version=version,
            exit_status=exit_status,
            artifacts_ref=artifacts_ref,
            evidence_location=evidence_location,
            timestamp=now_utc_iso(),
        )

    def forbid_self_approval(self, actor: str) -> None:
        """Yellow must never approve its own implementation. Refuse any actor
        that could hold an approval role toward its own verified work."""
        if self.registry is not None and self.registry.has_role(actor, "ci-operator"):
            raise SelfApprovalError(
                f"yellow agent '{actor}' cannot approve its own implementation"
            )