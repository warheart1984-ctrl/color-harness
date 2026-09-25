"""Purple Team: closure validation — maps findings to controls and proves (by
independent re-test evidence) that a remediation actually closes the finding.

Purple is read-only and can never declare closure without re-test evidence.
Closures are persisted as `remediation` evidence by the white team
(``WhiteTeam.record_purple_output``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from ._common import now_utc_iso

CLOSURE_VERDICTS: frozenset[str] = frozenset({"open", "closed"})


class PurpleTeamError(Exception):
    pass


class PurpleNoReTestError(PurpleTeamError):
    pass


class PurpleUnauthorizedActorError(PurpleTeamError):
    pass


class InvalidClosureError(PurpleTeamError):
    pass


@dataclass(frozen=True)
class Closure:
    """A closure verdict on one finding, backed by re-test evidence."""

    closure_id: str
    task_id: str
    actor: str
    finding_ref: str
    controls: tuple[str, ...]
    re_test_refs: tuple[str, ...]
    verdict: str
    notes: str
    timestamp: str

    def __post_init__(self) -> None:
        if not self.finding_ref.strip():
            raise InvalidClosureError("a closure must reference its finding")
        if self.verdict not in CLOSURE_VERDICTS:
            raise InvalidClosureError(
                f"verdict must be one of {sorted(CLOSURE_VERDICTS)}"
            )
        if not self.re_test_refs:
            raise PurpleNoReTestError(
                "purple cannot declare closure without re-test evidence"
            )
        if self.verdict == "closed" and not self.controls:
            raise InvalidClosureError(
                "a closed finding must name the controls that close it"
            )


class PurpleTeam:
    PURPLE_ID = "purple.clo-1"

    def __init__(self, registry=None):
        self.registry = registry
        self.governance = None

    def _check_actor(self, actor: str) -> None:
        if self.registry is None or not self.registry.is_registered(actor):
            raise PurpleUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "purple":
            raise PurpleUnauthorizedActorError(
                f"actor '{actor}' is not a purple team agent"
            )

    def validate_closure(
        self,
        task_id: str,
        *,
        actor: str,
        finding_ref: str,
        controls: tuple[str, ...],
        re_test_refs: tuple[str, ...],
        verdict: str,
        notes: str = "",
    ) -> Closure:
        self._check_actor(actor)
        if verdict == "closed":
            if self.governance is None:
                raise PurpleNoReTestError("purple needs ledger access to verify re-test evidence")
            for ref in re_test_refs:
                record = self.governance.ledger.get(ref)
                if (record is None or record.task_id != task_id
                        or record.record_type != "test_result"
                        or (record.payload or {}).get("exit_status") != 0):
                    raise PurpleNoReTestError(
                        f"re-test reference '{ref}' is not a passing test result for this task"
                    )
        return Closure(
            closure_id=f"clo-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            finding_ref=finding_ref,
            controls=tuple(controls),
            re_test_refs=tuple(re_test_refs),
            verdict=verdict,
            notes=notes,
            timestamp=now_utc_iso(),
        )
