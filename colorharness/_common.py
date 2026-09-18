"""Core types, state machine table, and ownership rules for the coordinator."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ATHP-parity retention window for approvals and manifests.
RETENTION_DAYS = 90
APPROVAL_TTL_SECONDS = RETENTION_DAYS * 24 * 3600


class TaskState(str, Enum):
    INTAKE = "INTAKE"
    OBSERVE = "OBSERVE"
    DIAGNOSE = "DIAGNOSE"
    PLAN = "PLAN"
    BUILD = "BUILD"
    VERIFY = "VERIFY"
    APPROVE = "APPROVE"
    RELEASE = "RELEASE"
    MONITOR = "MONITOR"
    CLOSED = "CLOSED"
    BLOCKED = "BLOCKED"
    ESCALATED = "ESCALATED"
    ROLLED_BACK = "ROLLED_BACK"


class Trigger(str, Enum):
    CREATED = "CREATED"
    ROUTE = "ROUTE"
    OBSERVATIONS_READY = "OBSERVATIONS_READY"
    DIAGNOSIS_ACCEPTED = "DIAGNOSIS_ACCEPTED"
    PLAN_APPROVED = "PLAN_APPROVED"
    IMPLEMENTATION_READY = "IMPLEMENTATION_READY"
    VERIFICATION_PASSED = "VERIFICATION_PASSED"
    RELEASE_APPROVED = "RELEASE_APPROVED"
    DEPLOYED = "DEPLOYED"
    SUCCESS_CONFIRMED = "SUCCESS_CONFIRMED"
    BLOCK = "BLOCK"
    UNBLOCK = "UNBLOCK"
    ESCALATE = "ESCALATE"
    DECISION_RESUME = "DECISION_RESUME"
    ROLLBACK_INITIATED = "ROLLBACK_INITIATED"


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"


class RejectionCode(str, Enum):
    STATE_INVALID = "STATE_INVALID"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_NOT_RECORDED = "EVIDENCE_NOT_RECORDED"
    ACTOR_UNKNOWN = "ACTOR_UNKNOWN"
    SCOPE_INVALID = "SCOPE_INVALID"
    TASK_NOT_FOUND = "TASK_NOT_FOUND"
    ABSORBING = "ABSORBING"
    PAUSED = "PAUSED"
    APPROVAL_MISSING = "APPROVAL_MISSING"
    SCOPE_OUT_OF_BOUNDS = "SCOPE_OUT_OF_BOUNDS"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    AUTH_INVALID = "AUTH_INVALID"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    AGENT_QUARANTINED = "AGENT_QUARANTINED"


PATH_TRANSITIONS: dict[tuple[TaskState, Trigger], TaskState] = {
    (TaskState.INTAKE, Trigger.ROUTE): TaskState.OBSERVE,
    (TaskState.OBSERVE, Trigger.OBSERVATIONS_READY): TaskState.DIAGNOSE,
    (TaskState.DIAGNOSE, Trigger.DIAGNOSIS_ACCEPTED): TaskState.PLAN,
    (TaskState.PLAN, Trigger.PLAN_APPROVED): TaskState.BUILD,
    (TaskState.BUILD, Trigger.IMPLEMENTATION_READY): TaskState.VERIFY,
    (TaskState.VERIFY, Trigger.VERIFICATION_PASSED): TaskState.APPROVE,
    (TaskState.APPROVE, Trigger.RELEASE_APPROVED): TaskState.RELEASE,
    (TaskState.RELEASE, Trigger.DEPLOYED): TaskState.MONITOR,
    (TaskState.MONITOR, Trigger.SUCCESS_CONFIRMED): TaskState.CLOSED,
    (TaskState.RELEASE, Trigger.ROLLBACK_INITIATED): TaskState.ROLLED_BACK,
    (TaskState.MONITOR, Trigger.ROLLBACK_INITIATED): TaskState.ROLLED_BACK,
}

OPEN_TRIGGERS: frozenset[Trigger] = frozenset({Trigger.BLOCK, Trigger.ESCALATE})

RESOLUTION_TRIGGERS: frozenset[Trigger] = frozenset({Trigger.UNBLOCK, Trigger.DECISION_RESUME})

# Triggers that may only fire once the required evidence has actually been
# recorded in the ledger. Maps the trigger to the evidence record type it needs.
EVIDENCE_GATED_TRIGGERS: dict[Trigger, str] = {
    Trigger.OBSERVATIONS_READY: "observation",
    Trigger.DIAGNOSIS_ACCEPTED: "diagnosis",
    Trigger.IMPLEMENTATION_READY: "change",
}

ABSORBING: frozenset[TaskState] = frozenset({TaskState.CLOSED, TaskState.ROLLED_BACK})

RESUME_HOLDING: frozenset[TaskState] = frozenset({TaskState.BLOCKED, TaskState.ESCALATED})


def can_block(state: TaskState) -> bool:
    return state not in ABSORBING and state not in RESUME_HOLDING


def can_escalate(state: TaskState) -> bool:
    return state not in ABSORBING and state != TaskState.ESCALATED


def resolve_next_state(
    current: TaskState,
    trigger: Trigger,
    resume_state: TaskState | None,
) -> TaskState | None:
    direct = PATH_TRANSITIONS.get((current, trigger))
    if direct is not None:
        return direct
    if trigger == Trigger.UNBLOCK and current == TaskState.BLOCKED:
        return resume_state
    if trigger == Trigger.DECISION_RESUME and current == TaskState.ESCALATED:
        return resume_state
    if trigger == Trigger.BLOCK and current not in ABSORBING and current not in RESUME_HOLDING:
        return TaskState.BLOCKED
    if trigger == Trigger.ESCALATE and current not in ABSORBING and current != TaskState.ESCALATED:
        return TaskState.ESCALATED
    return None


STATE_OWNERS: dict[TaskState, frozenset[str]] = {
    TaskState.INTAKE: frozenset({"coordinator"}),
    TaskState.OBSERVE: frozenset({"observer", "blue", "purple", "red"}),
    TaskState.DIAGNOSE: frozenset({"black"}),
    TaskState.PLAN: frozenset({"gold", "coordinator"}),
    TaskState.BUILD: frozenset({"silver"}),
    TaskState.VERIFY: frozenset({"yellow"}),
    TaskState.APPROVE: frozenset({"yellow", "coordinator"}),
    TaskState.RELEASE: frozenset({"green"}),
    TaskState.MONITOR: frozenset({"green", "blue"}),
    TaskState.CLOSED: frozenset({"coordinator"}),
    TaskState.BLOCKED: frozenset({"*"}),
    TaskState.ESCALATED: frozenset({"*"}),
    TaskState.ROLLED_BACK: frozenset({"green"}),
}