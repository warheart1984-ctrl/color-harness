"""Phase 1 acceptance checks: coordinator, task state machine, registry,
event log, invalid-transition rejection, and restart idempotency."""

from __future__ import annotations

from colorharness import Coordinator, Observer, TeamRegistry
from colorharness import WhiteTeam
from colorharness.black import BlackTeam
from colorharness.silver import SilverTeam
from colorharness.yellow import YellowTeam
from colorharness._common import (
    RejectionCode,
    TaskState,
    Trigger,
    can_block,
    can_escalate,
)
from colorharness.registry import (
    CapabilityNotAllowedError,
    DuplicateAgentError,
    RegistrationError,
    UnknownTeamError,
)


def make_registry() -> TeamRegistry:
    reg = TeamRegistry()
    reg.register("observer.ro-1", "observer")
    reg.register("blue.obs-1", "blue", ("readonly_observe",))
    reg.register("black.diag-1", "black", ("readonly_diagnose",))
    reg.register("red.tar-1", "red", ("readonly_test",))
    reg.register("purple.clo-1", "purple", ("readonly_observe", "closure_validate"))
    reg.register("gold.plan-1", "gold", ("policy_write",))
    reg.register("silver.build-1", "silver", ("branch_write", "config_write"))
    reg.register("yellow.ver-1", "yellow", ("policy_check", "test"))
    reg.register("green.rel-1", "green", ("release_plan", "rollback_exec"))
    reg.register("white.sys-1", "white", ("ledger_write",))
    reg.grant_role("white.sys-1", "ci-operator")
    reg.grant_role("white.sys-1", "platform-owner")
    reg.grant_role("black.diag-1", "security-lead")
    return reg


def make_coordinator(tmp_path, registry: TeamRegistry | None = None) -> Coordinator:
    registry = registry or make_registry()
    governance = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl"))
    return Coordinator(registry=registry, store_path=str(tmp_path / "events.jsonl"), governance=governance)


FULL_PATH: list[tuple[Trigger, str, str]] = [
    (Trigger.ROUTE, Coordinator.SYSTEM_AGENT, "routing to observe"),
    (Trigger.OBSERVATIONS_READY, "blue.obs-1", "observations collected"),
    (Trigger.DIAGNOSIS_ACCEPTED, "black.diag-1", "diagnosis delivered"),
    (Trigger.PLAN_APPROVED, "gold.plan-1", "plan approved"),
    (Trigger.IMPLEMENTATION_READY, "silver.build-1", "implementation ready"),
    (Trigger.VERIFICATION_PASSED, "yellow.ver-1", "verification passed"),
    (Trigger.RELEASE_APPROVED, Coordinator.SYSTEM_AGENT, "release approved"),
    (Trigger.DEPLOYED, "green.rel-1", "deployed"),
    (Trigger.SUCCESS_CONFIRMED, "green.rel-1", "success confirmed"),
]


def _record_gate_evidence(c: Coordinator, task_id: str, trigger: Trigger) -> tuple[str, ...]:
    """Governed flows must record observation/diagnosis evidence before the
    gated transitions (EVIDENCE_GATED_TRIGGERS) fire. Skipped when the
    coordinator has no governance attached."""
    records = []
    if trigger == Trigger.OBSERVATIONS_READY:
        obs = Observer().collect(
            task_id=task_id, observation_type="metrics",
            detail={"metric": "error_rate", "value": 0.0},
            source="observer://helper",
        )
        records = c.governance.record_observations(task_id, (obs,))
    elif trigger == Trigger.DIAGNOSIS_ACCEPTED:
        observation = next(
            r for r in reversed(c.governance.ledger.records)
            if r.task_id == task_id and r.record_type == "observation"
        )
        diag = BlackTeam(registry=c.registry).diagnose(
            task_id=task_id, actor="black.diag-1",
            diagnosis="baseline healthy", confidence="medium",
            evidence_refs=(observation.evidence_id,),
            alternatives=("flaky metric", "noise"),
        )
        records = c.governance.record_black_output(task_id, (diag,))
    elif trigger == Trigger.IMPLEMENTATION_READY:
        plan = next(
            r for r in reversed(c.governance.ledger.records)
            if r.task_id == task_id and r.record_type == "approval"
            and r.payload.get("gated_action") == "plan_approval"
        )
        change = SilverTeam(registry=c.registry).present_change(
            task_id=task_id, actor="silver.build-1",
            change_type="branch", branch="isolated/helper",
            files=("deploy.yaml",), diff_summary="helper implementation",
            plan_refs=(plan.evidence_id,),
            rollback_metadata={"steps": ["git revert helper"]},
        )
        records = c.governance.record_silver_output(task_id, (change,))
    elif trigger == Trigger.VERIFICATION_PASSED:
        result = YellowTeam(registry=c.registry).run_check(
            task_id=task_id, actor="yellow.ver-1",
            check_type="readiness", command="pytest -q", version="pytest 9.1.1",
            exit_status=0, artifacts_ref="log://helper",
            evidence_location="report://helper",
        )
        records = c.governance.record_yellow_output(task_id, (result,))
    elif trigger == Trigger.PLAN_APPROVED:
        risk = c.governance.current_risk(task_id).value
        approver, role = (("white.sys-1", "ci-operator") if risk in {"green", "yellow"}
                          else ("black.diag-1", "security-lead"))
        approval = c.governance.record_approval(
            task_id, gated_action="plan_approval", approver=approver,
            scope=c.governance.get_scope(task_id).scope, author="silver.build-1", approver_role=role,
        )
        records = [c.governance.ledger.get(approval.evidence_id)]
    elif trigger == Trigger.RELEASE_APPROVED:
        if not c.governance.approval_quorum_met(task_id, "release"):
            security = c.governance.record_approval(
                task_id, gated_action="release", approver="black.diag-1",
                scope=c.governance.get_scope(task_id).scope, author="silver.build-1",
                approver_role="security-lead",
            )
            platform = c.governance.record_approval(
                task_id, gated_action="release", approver="white.sys-1",
                scope=c.governance.get_scope(task_id).scope, author="silver.build-1",
                approver_role="platform-owner",
            )
            records = [c.governance.ledger.get(security.evidence_id),
                       c.governance.ledger.get(platform.evidence_id)]
    elif trigger == Trigger.ROLLBACK_INITIATED:
        security = c.governance.record_approval(
            task_id, gated_action="rollback", approver="black.diag-1",
            scope=c.governance.get_scope(task_id).scope, author="green.rel-1",
            approver_role="security-lead",
        )
        platform = c.governance.record_approval(
            task_id, gated_action="rollback", approver="white.sys-1",
            scope=c.governance.get_scope(task_id).scope, author="green.rel-1",
            approver_role="platform-owner",
        )
        records = [c.governance.ledger.get(security.evidence_id),
                   c.governance.ledger.get(platform.evidence_id)]
    return tuple(record.evidence_id for record in records if record is not None)


def drive_full_path(c: Coordinator, task_id: str, prefix: str = "") -> list[str]:
    request_ids = []
    for trigger, actor, reason in FULL_PATH:
        rid = f"{prefix}rid-{trigger.value}"
        refs = _record_gate_evidence(c, task_id, trigger)
        result = c.apply_transition(
            task_id, trigger, actor=actor, reason=reason,
            evidence_refs=refs or (f"log://{rid}",), request_id=rid,
        )
        assert result["success"], result.get("error")
        request_ids.append(rid)
    return request_ids


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_registration_basics() -> None:
    reg = make_registry()
    assert reg.team_of("black.diag-1") == "black"
    assert reg.agents_for("yellow") == ["yellow.ver-1"]
    assert reg.is_registered("blue.obs-1")


def test_registration_rejects_unknown_team() -> None:
    reg = TeamRegistry()
    try:
        reg.register("x.1", "mauve", ())
    except UnknownTeamError:
        pass
    else:
        raise AssertionError("unknown team must be rejected")


def test_registration_rejects_duplicate_agent() -> None:
    reg = make_registry()
    try:
        reg.register("black.diag-1", "white", ())
    except DuplicateAgentError:
        pass
    else:
        raise AssertionError("duplicate agent_id must be rejected")


def test_registration_rejects_out_of_charter_capability() -> None:
    reg = TeamRegistry()
    try:
        reg.register("over.a-1", "observer", ("release_plan",))
    except CapabilityNotAllowedError:
        pass
    else:
        raise AssertionError("capability outside team charter must be rejected")


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def test_create_task_sets_intake_state(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="build pipeline", scope={"repo": "color-harness"})
    assert task["state"] == TaskState.INTAKE.value
    assert task["task_id"].startswith("task-")
    assert task["correlation_id"] == f"corr-{task['task_id']}"
    assert task["risk"] == "yellow"


def test_create_task_is_idempotent(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    a = c.create_task(title="t", scope={"repo": "test"})
    b = c.create_task(task_id=a["task_id"], title="t", scope={"repo": "test"})
    assert a == b
    assert c.event_count() == 1


# ---------------------------------------------------------------------------
# Happy path + transition record completeness
# ---------------------------------------------------------------------------

def test_full_lifecycle_closes(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="change", scope={"repo": "r"})
    drive_full_path(c, task["task_id"])
    assert c.get_task(task["task_id"])["state"] == TaskState.CLOSED.value


def test_forged_evidence_reference_does_not_unlock_gate(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="evidence gate", scope={"repo": "test"})
    tid = task["task_id"]
    c.apply_transition(tid, Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("external://route",), request_id="gate-route")
    obs = Observer().collect(task_id=tid, observation_type="metrics",
                             detail={"metric": "error_rate", "value": 0.2},
                             source="observer://test")
    c.governance.record_observations(tid, (obs,))
    result = c.apply_transition(tid, Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
                                reason="observed", evidence_refs=("forged-evidence-id",),
                                request_id="gate-forged")
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.EVIDENCE_NOT_RECORDED.value


def test_every_transition_records_actor_timestamp_reason_evidence(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="change", scope={"repo": "r"})
    drive_full_path(c, task["task_id"])
    events = c.events()
    for event in events:
        assert event.actor.strip(), f"{event.event_id} missing actor"
        assert event.timestamp.strip(), f"{event.event_id} missing timestamp"
        assert event.reason.strip(), f"{event.event_id} missing reason"
        assert event.evidence_refs, f"{event.event_id} missing evidence references"
        assert event.decision_id.startswith("dec-")
        if event.outcome == "SUCCESS" and event.trigger != Trigger.CREATED.value:
            assert event.from_state is not None and event.to_state is not None


def test_correlation_id_stable_and_seq_monotonic(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="change", scope={"repo": "test"})
    drive_full_path(c, task["task_id"])
    events = c.events()
    corr = {e.correlation_id for e in events}
    assert len(corr) == 1
    seqs = [e.seq for e in events]
    assert seqs == sorted(seqs)
    assert seqs[0] == 1


def test_can_block_and_escalate_auxiliary(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    assert can_block(TaskState(task["state"]))
    c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="route", evidence_refs=("x",), request_id="r-route",
    )
    assert can_escalate(TaskState.OBSERVE)


# ---------------------------------------------------------------------------
# Invalid transitions rejected + recorded
# ---------------------------------------------------------------------------

def test_illegal_transition_rejected_and_recorded(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    result = c.apply_transition(
        task["task_id"], Trigger.VERIFICATION_PASSED, actor=Coordinator.SYSTEM_AGENT,
        reason="out of order", evidence_refs=("x",), request_id="r-early",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.STATE_INVALID.value
    assert c.get_task(task["task_id"])["state"] == TaskState.INTAKE.value
    rejected = [e for e in c.events() if e.outcome == "REJECTED"]
    assert rejected and rejected[0].error_code == RejectionCode.STATE_INVALID.value


def test_absorbing_states_reject_all_transitions(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    drive_full_path(c, task["task_id"])
    tid = task["task_id"]
    assert c.get_task(tid)["state"] == TaskState.CLOSED.value
    result = c.apply_transition(
        task["task_id"], Trigger.SUCCESS_CONFIRMED, actor="green.rel-1",
        reason="again", evidence_refs=("x",), request_id="r-after-close",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.ABSORBING.value


def test_wrong_team_rejected_as_scope(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    c.apply_transition(task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("x",), request_id="r-route")
    result = c.apply_transition(
        task["task_id"], Trigger.OBSERVATIONS_READY, actor="silver.build-1",
        reason="not my stage", evidence_refs=("x",), request_id="r-wrong-team",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.SCOPE_INVALID.value


def test_unknown_actor_rejected(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    result = c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor="ghost.1",
        reason="y", evidence_refs=("x",), request_id="r-ghost",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.ACTOR_UNKNOWN.value


def test_missing_evidence_rejected(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    result = c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="y", evidence_refs=(), request_id="r-no-evidence",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.EVIDENCE_MISSING.value


# ---------------------------------------------------------------------------
# Block / escalate / rollback
# ---------------------------------------------------------------------------

def _advance_to(c: Coordinator, task_id: str, wanted: TaskState) -> None:
    next_step = {
        TaskState.INTAKE: FULL_PATH[0], TaskState.OBSERVE: FULL_PATH[1],
        TaskState.DIAGNOSE: FULL_PATH[2], TaskState.PLAN: FULL_PATH[3],
        TaskState.BUILD: FULL_PATH[4], TaskState.VERIFY: FULL_PATH[5],
        TaskState.APPROVE: FULL_PATH[6], TaskState.RELEASE: FULL_PATH[7],
        TaskState.MONITOR: FULL_PATH[8],
    }
    while TaskState(c.get_task(task_id)["state"]) != wanted:
        current = TaskState(c.get_task(task_id)["state"])
        if current not in next_step:
            raise AssertionError(f"cannot advance from {current.value} to {wanted.value}")
        trigger, actor, reason = next_step[current]
        refs = _record_gate_evidence(c, task_id, trigger)
        result = c.apply_transition(task_id, trigger, actor=actor, reason=reason,
                                    evidence_refs=refs or (f"log://{reason}",),
                                    request_id=f"rid-{reason}-{len(c.events())}")
        assert result["success"], result.get("error")


def test_block_and_unblock_resumes(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    _advance_to(c, task["task_id"], TaskState.DIAGNOSE)
    blk = c.apply_transition(task["task_id"], Trigger.BLOCK, actor="black.diag-1",
                             reason="missing artifact", evidence_refs=("log://block",),
                             request_id="r-block")
    assert blk["success"] and blk["event"]["to_state"] == TaskState.BLOCKED.value
    assert c.get_task(task["task_id"])["resume_state"] == TaskState.DIAGNOSE.value
    unblk = c.apply_transition(task["task_id"], Trigger.UNBLOCK, actor=Coordinator.SYSTEM_AGENT,
                               reason="artifact found", evidence_refs=("log://unblock",),
                               request_id="r-unblock")
    assert unblk["success"]
    assert c.get_task(task["task_id"])["state"] == TaskState.DIAGNOSE.value
    _advance_to(c, task["task_id"], TaskState.CLOSED)
    assert c.get_task(task["task_id"])["state"] == TaskState.CLOSED.value


def test_escalate_and_decision_resume(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    _advance_to(c, task["task_id"], TaskState.BUILD)
    esc = c.apply_transition(task["task_id"], Trigger.ESCALATE, actor="silver.build-1",
                             reason="needs authority", evidence_refs=("log://esc",),
                             request_id="r-esc")
    assert esc["event"]["to_state"] == TaskState.ESCALATED.value
    resume = c.apply_transition(task["task_id"], Trigger.DECISION_RESUME,
                                actor=Coordinator.SYSTEM_AGENT, reason="approved higher",
                                evidence_refs=("log://resume",), request_id="r-resume")
    assert resume["success"] and c.get_task(task["task_id"])["state"] == TaskState.BUILD.value


def test_unauthorized_resolution_rejected(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    _advance_to(c, task["task_id"], TaskState.BUILD)
    c.apply_transition(task["task_id"], Trigger.ESCALATE, actor="silver.build-1",
                       reason="escalate", evidence_refs=("x",), request_id="r-esc2")
    result = c.apply_transition(task["task_id"], Trigger.DECISION_RESUME,
                                actor="silver.build-1", reason="not my call",
                                evidence_refs=("x",), request_id="r-bad-resume")
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.AUTH_INVALID.value


def test_rollback_reachable_and_absorbing(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={"repo": "test"})
    _advance_to(c, task["task_id"], TaskState.RELEASE)
    rollback_refs = _record_gate_evidence(c, task["task_id"], Trigger.ROLLBACK_INITIATED)
    rb = c.apply_transition(task["task_id"], Trigger.ROLLBACK_INITIATED, actor="green.rel-1",
                            reason="rollout degraded", evidence_refs=rollback_refs,
                            request_id="r-rb")
    assert rb["event"]["to_state"] == TaskState.ROLLED_BACK.value
    again = c.apply_transition(task["task_id"], Trigger.DEPLOYED, actor="green.rel-1",
                               reason="retry", evidence_refs=("x",), request_id="r-rb2")
    assert again["success"] is False
    assert again["error"]["code"] == RejectionCode.ABSORBING.value


# ---------------------------------------------------------------------------
# Restart idempotency
# ---------------------------------------------------------------------------

def test_restart_restores_state_and_replays_without_duplication(tmp_path) -> None:
    registry = make_registry()
    store = str(tmp_path / "events.jsonl")
    gov1 = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl"))
    c1 = Coordinator(registry=registry, store_path=store, governance=gov1)
    task = c1.create_task(title="change", scope={"repo": "r"})
    drive_full_path(c1, task["task_id"])
    final_state = c1.get_task(task["task_id"])["state"]
    count_before = c1.event_count()

    gov2 = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl"))
    c2 = Coordinator(registry=registry, store_path=store, governance=gov2)
    assert c2.get_task(task["task_id"])["state"] == final_state
    assert c2.event_count() == count_before

    replay = c2.apply_transition(
        task["task_id"], Trigger.SUCCESS_CONFIRMED, actor="green.rel-1",
        reason="success confirmed", evidence_refs=("log://rid-SUCCESS_CONFIRMED",),
        request_id="rid-SUCCESS_CONFIRMED",
    )
    assert replay["success"] is True
    assert c2.event_count() == count_before


def test_restart_continues_sequence_without_gap(tmp_path) -> None:
    registry = make_registry()
    store = str(tmp_path / "events.jsonl")
    gov1 = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger-seq.jsonl"))
    c1 = Coordinator(registry=registry, store_path=store, governance=gov1)
    task = c1.create_task(title="change", scope={"repo": "test"})
    drive_full_path(c1, task["task_id"])
    count_before = c1.event_count()
    events_for_task1 = [e for e in c1.events() if e.task_id == task["task_id"]]

    gov2 = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger-seq.jsonl"))
    c2 = Coordinator(registry=registry, store_path=store, governance=gov2)
    task2 = c2.create_task(title="second", scope={"repo": "test"})
    assert task2["task_id"] != task["task_id"]
    drive_full_path(c2, task2["task_id"], prefix="t2-")

    events_for_task2 = [e for e in c2.events() if e.task_id == task2["task_id"]]
    assert [e.seq for e in events_for_task2] == list(range(1, len(events_for_task2) + 1))
    assert c2.event_count() == count_before + len(events_for_task2)
    assert c2.get_task(task["task_id"])["state"] == TaskState.CLOSED.value


def test_missing_task_rejected_without_event(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    before = c.event_count()
    result = c.apply_transition("task-nope", Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                                reason="r", evidence_refs=("x",), request_id="r-nope")
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.TASK_NOT_FOUND.value
    assert c.event_count() == before
