"""Coordinator: task routing, state transition validation, and replay."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Optional

from ._common import (
    ABSORBING,
    OPEN_TRIGGERS,
    RESOLUTION_TRIGGERS,
    RESUME_HOLDING,
    STATE_OWNERS,
    TaskState,
    Trigger,
    RejectionCode,
    can_block,
    can_escalate,
    now_utc_iso,
    resolve_next_state,
)
from .eventlog import Event, EventLog
from .governance import GOVERNED_ACTIONS
from .registry import TeamRegistry

if TYPE_CHECKING:
    from .governance import WhiteTeam


class Coordinator:
    SYSTEM_AGENT = "coordinator.system"

    def __init__(
        self,
        registry: Optional[TeamRegistry] = None,
        store_path: Optional[str] = None,
        governance: Optional["WhiteTeam"] = None,
    ):
        self.registry = registry or TeamRegistry()
        if not self.registry.is_registered(self.SYSTEM_AGENT):
            self.registry.register(
                self.SYSTEM_AGENT,
                "coordinator",
                ("route", "transition", "record"),
            )
        self.governance = governance
        self.log = EventLog(store_path)
        self._tasks: dict[str, dict[str, Any]] = {}
        self._replay()

    # ------------------------------------------------------------------
    # Task intake
    # ------------------------------------------------------------------

    def create_task(
        self,
        task_id: Optional[str] = None,
        *,
        title: str,
        scope: dict,
        risk: str = "yellow",
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        actor: str = SYSTEM_AGENT,
        reason: str = "task intake declared",
        evidence_refs: tuple[str, ...] = (),
    ) -> dict:
        task_id = task_id or f"task-{uuid.uuid4().hex[:12]}"
        existing = self._tasks.get(task_id)
        if existing is not None:
            return existing
        correlation_id = correlation_id or f"corr-{task_id}"
        request_id = request_id or f"req-{uuid.uuid4().hex[:12]}"
        evidence_refs = evidence_refs or (f"task://{task_id}",)

        task = {
            "task_id": task_id,
            "correlation_id": correlation_id,
            "title": title,
            "scope": dict(scope),
            "risk": risk,
            "state": TaskState.INTAKE.value,
            "resume_state": None,
            "seq": 0,
            "created_at": now_utc_iso(),
        }
        event = Event(
            event_id=f"evt-{uuid.uuid4().hex[:16]}",
            task_id=task_id,
            correlation_id=correlation_id,
            seq=1,
            request_id=request_id,
            trigger=Trigger.CREATED.value,
            actor=actor,
            timestamp=now_utc_iso(),
            reason=reason,
            outcome="SUCCESS",
            from_state=None,
            to_state=TaskState.INTAKE.value,
            decision_id=self._new_decision_id(),
            evidence_refs=tuple(evidence_refs),
            payload={
                "title": title,
                "scope": dict(scope),
                "risk": risk,
            },
        )
        result = self.log.append(event)
        self._apply(event, task)
        self._tasks[task_id] = task
        if self.governance is not None:
            self.governance.declare_scope(
                task_id,
                declared_by=actor,
                scope=dict(scope),
                risk=risk,
                correlation_id=correlation_id,
            )
        return self._public_task(task)

    # ------------------------------------------------------------------
    # Transitions
    # ------------------------------------------------------------------

    def apply_transition(
        self,
        task_id: str,
        trigger: Trigger,
        *,
        actor: str,
        reason: str,
        evidence_refs: tuple[str, ...],
        request_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> dict:
        request_id = request_id or f"req-{uuid.uuid4().hex[:12]}"
        cached = self.log.seen(task_id, request_id)
        if cached is not None:
            return cached

        task = self._tasks.get(task_id)
        if task is None:
            return self._rejection(
                task_id,
                request_id,
                trigger,
                actor,
                RejectionCode.TASK_NOT_FOUND,
                f"no task with id '{task_id}'",
                recorded=False,
            )
        if (
            self.governance is not None
            and self.governance.is_paused(task_id)
            and trigger not in RESOLUTION_TRIGGERS
        ):
            return self._record_rejection(
                task, trigger, actor, request_id,
                RejectionCode.PAUSED,
                "task is paused by the white team",
            )
        if not evidence_refs:
            return self._record_rejection(
                task, trigger, actor, request_id,
                RejectionCode.EVIDENCE_MISSING,
                "a transition requires at least one evidence reference",
            )
        try:
            team = self.registry.team_of(actor)
        except KeyError:
            return self._record_rejection(
                task, trigger, actor, request_id,
                RejectionCode.ACTOR_UNKNOWN,
                f"actor '{actor}' is not a registered agent",
            )

        current = TaskState(task["state"])
        resume_state = TaskState(task["resume_state"]) if task["resume_state"] else None

        if current in ABSORBING:
            return self._record_rejection(
                task, trigger, actor, request_id,
                RejectionCode.ABSORBING,
                f"task is in absorbing state '{current.value}'",
            )
        if trigger in OPEN_TRIGGERS:
            allowed = (trigger == Trigger.BLOCK and can_block(current)) or (
                trigger == Trigger.ESCALATE and can_escalate(current)
            )
            if not allowed:
                return self._record_rejection(
                    task, trigger, actor, request_id,
                    RejectionCode.STATE_INVALID,
                    f"cannot {trigger.value} from state '{current.value}'",
                )
        elif trigger in RESOLUTION_TRIGGERS:
            if team not in ("coordinator", "white"):
                return self._record_rejection(
                    task, trigger, actor, request_id,
                    RejectionCode.SCOPE_INVALID,
                    f"team '{team}' may not resolve '{trigger.value}'",
                )
        else:
            owners = STATE_OWNERS.get(current, frozenset())
            if "*" not in owners and team not in owners:
                return self._record_rejection(
                    task, trigger, actor, request_id,
                    RejectionCode.SCOPE_INVALID,
                    f"team '{team}' does not own state '{current.value}'",
                )

        governed_action = action or GOVERNED_ACTIONS.get(trigger)
        if governed_action and self.governance is not None:
            requested_scope = None
            declaration = self.governance.get_scope(task_id)
            if declaration is not None:
                requested_scope = declaration.scope
            if not self.governance.has_valid_approval(
                task_id, governed_action, requested_scope=requested_scope
            ):
                return self._record_rejection(
                    task, trigger, actor, request_id,
                    RejectionCode.APPROVAL_MISSING,
                    f"no valid approval for protected action '{governed_action}'",
                )

        new_state = resolve_next_state(current, trigger, resume_state)
        if new_state is None:
            return self._record_rejection(
                task, trigger, actor, request_id,
                RejectionCode.STATE_INVALID,
                f"no legal transition from '{current.value}' on trigger '{trigger.value}'",
            )

        hold_resume = new_state in RESUME_HOLDING
        event = Event(
            event_id=f"evt-{uuid.uuid4().hex[:16]}",
            task_id=task["task_id"],
            correlation_id=task["correlation_id"],
            seq=task["seq"] + 1,
            request_id=request_id,
            trigger=trigger.value,
            actor=actor,
            timestamp=now_utc_iso(),
            reason=reason,
            outcome="SUCCESS",
            from_state=current.value,
            to_state=new_state.value,
            resume_state=current.value if hold_resume else None,
            decision_id=self._new_decision_id(),
            evidence_refs=tuple(evidence_refs),
        )
        result = self.log.append(event)
        self._apply(event, task)
        if self.governance is not None:
            self.governance.record_transition(event)
        return result

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_task(self, task_id: str) -> Optional[dict]:
        task = self._tasks.get(task_id)
        return self._public_task(task) if task else None

    def tasks(self) -> list[dict]:
        return [self._public_task(t) for t in self._tasks.values()]

    def task_exists(self, task_id: str) -> bool:
        return task_id in self._tasks

    def events(self) -> list[Event]:
        return list(self.log.events)

    def event_count(self) -> int:
        return len(self.log.events)

    @property
    def store_path(self) -> Optional[str]:
        return self.log.path

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _new_decision_id() -> str:
        return f"dec-{uuid.uuid4()}"

    @staticmethod
    def _apply(event: Event, task: dict) -> None:
        if event.outcome != "SUCCESS":
            return
        task["state"] = event.to_state
        if event.to_state in RESUME_HOLDING:
            task["resume_state"] = event.resume_state
        else:
            task["resume_state"] = None
        task["seq"] = max(task["seq"], event.seq)

    def _rejection(
        self,
        task_id: str,
        request_id: str,
        trigger: Trigger,
        actor: str,
        code: RejectionCode,
        detail: str,
        *,
        recorded: bool,
    ) -> dict:
        if not recorded:
            return self._rejection_dict(task_id, request_id, None, code, detail)
        return self._record_rejection(
            self._tasks[task_id], trigger, actor, "", request_id, code, detail,
        )

    def _rejection_dict(
        self,
        task_id: str,
        request_id: str,
        event: Event | None,
        code: RejectionCode,
        detail: str,
    ) -> dict:
        return {
            "request_id": request_id,
            "task_id": task_id,
            "success": False,
            "event": event.to_dict() if event else None,
            "error": {"code": code.value, "detail": detail},
        }

    def _record_rejection(
        self,
        task: dict,
        trigger: Trigger,
        actor: str,
        request_id: str,
        code: RejectionCode,
        detail: str,
    ) -> dict:
        event = Event(
            event_id=f"evt-{uuid.uuid4().hex[:16]}",
            task_id=task["task_id"],
            correlation_id=task["correlation_id"],
            seq=task["seq"] + 1,
            request_id=request_id,
            trigger=trigger.value,
            actor=actor,
            timestamp=now_utc_iso(),
            reason=detail,
            outcome="REJECTED",
            from_state=task["state"],
            to_state=None,
            error_code=code.value,
            evidence_refs=(),
        )
        task["seq"] = max(task["seq"], event.seq)
        result = self.log.append(event)
        return result

    def _replay(self) -> None:
        for event in self.log.events:
            task = self._tasks.get(event.task_id)
            if task is None:
                corr = event.correlation_id
                payload = event.payload or {}
                task = {
                    "task_id": event.task_id,
                    "correlation_id": corr,
                    "title": payload.get("title", event.task_id),
                    "scope": payload.get("scope", {}),
                    "risk": payload.get("risk", "unknown"),
                    "state": "INTAKE",
                    "resume_state": None,
                    "seq": 0,
                    "created_at": event.timestamp,
                }
                self._tasks[event.task_id] = task
            self._apply(event, task)

    @staticmethod
    def _public_task(task: dict) -> dict:
        return dict(task)