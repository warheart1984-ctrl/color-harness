"""Phase 1 acceptance checks: coordinator, task state machine, registry,
event log, invalid-transition rejection, and restart idempotency."""

from __future__ import annotations

from colorharness import Coordinator, Observer, TeamRegistry
from colorharness.black import BlackTeam
from colorharness.silver import SilverTeam
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
    reg.register("gold.plan-1", "gold", ("policy_write",))
    reg.register("silver.build-1", "silver", ("branch_write", "config_write"))
    reg.register("yellow.ver-1", "yellow", ("policy_check", "test"))
    reg.register("green.rel-1", "green", ("release_plan", "rollback_exec"))
    reg.register("white.sys-1", "white", ("ledger_write",))
    reg.grant_role("white.sys-1", "ci-operator")
    return reg


def make_coordinator(tmp_path, registry: TeamRegistry | None = None) -> Coordinator:
    return Coordinator(registry=registry or make_registry(), store_path=str(tmp_path / "events.jsonl"))


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


def _record_gate_evidence(c: Coordinator, task_id: str, trigger: Trigger) -> None:
    """Governed flows must record observation/diagnosis evidence before the
    gated transitions (EVIDENCE_GATED_TRIGGERS) fire. Skipped when the
    coordinator has no governance attached."""
    if c.governance is None:
        return
    if trigger == Trigger.OBSERVATIONS_READY:
        obs = Observer().collect(
            task_id=task_id, observation_type="metrics",
            detail={"metric": "error_rate", "value": 0.0},
            source="observer://helper",
        )
        c.governance.record_observations(task_id, (obs,))
    elif trigger == Trigger.DIAGNOSIS_ACCEPTED:
        diag = BlackTeam(registry=c.registry).diagnose(
            task_id=task_id, actor="black.diag-1",
            diagnosis="baseline healthy", confidence="medium",
            evidence_refs=("log://helper",),
            alternatives=("flaky metric", "noise"),
        )
        c.governance.record_black_output(task_id, (diag,))
    elif trigger == Trigger.IMPLEMENTATION_READY:
        change = SilverTeam(registry=c.registry).present_change(
            task_id=task_id, actor="silver.build-1",
            change_type="branch", branch="isolated/helper",
            files=("deploy.yaml",), diff_summary="helper implementation",
            plan_refs=("log://helper",),
            rollback_metadata={"steps": ["git revert helper"]},
        )
        c.governance.record_silver_output(task_id, (change,))


def drive_full_path(c: Coordinator, task_id: str, prefix: str = "") -> list[str]:
    request_ids = []
    for trigger, actor, reason in FULL_PATH:
        rid = f"{prefix}rid-{trigger.value}"
        _record_gate_evidence(c, task_id, trigger)
        c.apply_transition(
            task_id, trigger, actor=actor, reason=reason,
            evidence_refs=(f"log://{rid}",), request_id=rid,
        )
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
    a = c.create_task(title="t", scope={})
    b = c.create_task(task_id=a["task_id"], title="t", scope={})
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
    task = c.create_task(title="change", scope={})
    drive_full_path(c, task["task_id"])
    events = c.events()
    corr = {e.correlation_id for e in events}
    assert len(corr) == 1
    seqs = [e.seq for e in events]
    assert seqs == sorted(seqs)
    assert seqs[0] == 1


def test_can_block_and_escalate_auxiliary(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
    result = c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor="ghost.1",
        reason="y", evidence_refs=("x",), request_id="r-ghost",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.ACTOR_UNKNOWN.value


def test_missing_evidence_rejected(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={})
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
    for trigger, actor, reason in FULL_PATH:
        if TaskState(c.get_task(task_id)["state"]) == wanted:
            return
        c.apply_transition(task_id, trigger, actor=actor, reason=reason,
                           evidence_refs=(f"log://{reason}",),
                           request_id=f"rid-{reason}")


def test_block_and_unblock_resumes(tmp_path) -> None:
    c = make_coordinator(tmp_path)
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
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
    task = c.create_task(title="t", scope={})
    _advance_to(c, task["task_id"], TaskState.RELEASE)
    rb = c.apply_transition(task["task_id"], Trigger.ROLLBACK_INITIATED, actor="green.rel-1",
                            reason="rollout degraded", evidence_refs=("log://rb",),
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
    c1 = Coordinator(registry=registry, store_path=store)
    task = c1.create_task(title="change", scope={"repo": "r"})
    drive_full_path(c1, task["task_id"])
    final_state = c1.get_task(task["task_id"])["state"]
    count_before = c1.event_count()

    c2 = Coordinator(registry=registry, store_path=store)
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
    c1 = Coordinator(registry=registry, store_path=store)
    task = c1.create_task(title="change", scope={})
    drive_full_path(c1, task["task_id"])
    count_before = c1.event_count()
    events_for_task1 = [e for e in c1.events() if e.task_id == task["task_id"]]

    c2 = Coordinator(registry=registry, store_path=store)
    task2 = c2.create_task(title="second", scope={})
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