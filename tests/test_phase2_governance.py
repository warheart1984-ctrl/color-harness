"""Phase 2 acceptance checks: White Team governance — scope declarations,
approvals, risk classification, evidence ledger (hash chain + completeness),
pause/escalation, append-only audit, and coordinator gating."""

from __future__ import annotations

import json

import pytest

from colorharness import (
    Coordinator,
    EvidenceLedger,
    IncompleteEvidenceError,
    LedgerImmutableError,
    NoSelfApprovalError,
    RiskRegressionError,
    ScopeApprovalRequired,
    TeamRegistry,
    WhiteTeam,
    scope_covers,
)
from colorharness._common import RejectionCode, TaskState, Trigger
from colorharness.risk import RiskClass
from tests.test_phase1_coordinator import (
    FULL_PATH,
    _record_gate_evidence,
    drive_full_path,
    make_registry,
)


def make_governed(tmp_path, registry=None) -> tuple[Coordinator, WhiteTeam, TeamRegistry]:
    reg = registry or make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "events.jsonl"), governance=gov)
    return c, gov, reg


SCOPE = {"environments": ["staging"], "resources": ["pipeline:build"]}
SCOPE = {"ci_cd": {"environments": ["staging"]}, "resources": ["pipeline:build"]}


def _drive_to(c: Coordinator, task_id: str, wanted: TaskState) -> None:
    for trigger, actor, reason in FULL_PATH:
        if TaskState(c.get_task(task_id)["state"]) == wanted:
            return
        refs = _record_gate_evidence(c, task_id, trigger)
        c.apply_transition(task_id, trigger, actor=actor, reason=reason,
                           evidence_refs=refs or (f"log://{reason}",), request_id=f"rid-{reason}")


# ---------------------------------------------------------------------------
# scope_covers unit behavior
# ---------------------------------------------------------------------------

def test_scope_covers_semantics() -> None:
    assert scope_covers({"a": [1, 2]}, {"a": [1]})
    assert not scope_covers({"a": [1]}, {"a": [1, 2]})
    assert scope_covers({"env": "staging"}, {"env": "staging"})
    assert not scope_covers({"env": "staging"}, {"env": "prod"})
    assert not scope_covers({"a": [1]}, {"a": [1], "b": [2]})


# ---------------------------------------------------------------------------
# Scope declarations
# ---------------------------------------------------------------------------

def test_scope_declared_on_task_intake(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE, risk="orange")
    decl = gov.get_scope(task["task_id"])
    assert decl is not None
    assert decl.risk == RiskClass.ORANGE
    assert decl.scope == SCOPE
    assert decl.version == 1
    assert any(r.record_type == "scope_declaration" for r in gov.ledger.records)


def test_scope_expansion_requires_approval(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    with pytest.raises(ScopeApprovalRequired):
        gov.expand_scope(
            task["task_id"],
            additions={"environments": ["production"]},
            actor="gold.plan-1",
            approval_id=None,
        )
    assert gov.get_scope(task["task_id"]).scope == SCOPE
    assert gov.get_scope(task["task_id"]).version == 1


def test_scope_expansion_with_approval_succeeds(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    approval = gov.record_approval(
        task["task_id"],
        gated_action="scope_expansion",
        approver="black.diag-1",
        approver_role="security-lead",
        scope={"ci_cd": {"environments": ["staging"]},
               "environments": ["staging", "production"],
               "resources": ["pipeline:build"]},
        author="gold.plan-1",
    )
    new = gov.expand_scope(
        task["task_id"],
        additions={"environments": ["production"]},
        actor="gold.plan-1",
        approval_id=approval.approval_id,
    )
    assert new.version == 2
    assert (set(new.scope["ci_cd"]["environments"])
            | set(new.scope["environments"])) == {"staging", "production"}


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------

def test_no_self_approval(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    with pytest.raises(NoSelfApprovalError):
        gov.record_approval(
            task["task_id"], gated_action="release",
            approver="silver.build-1", scope=SCOPE, author="silver.build-1",
        )


def test_approval_validity_scope_and_expiry(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    platform = gov.record_approval(
        task["task_id"], gated_action="release", approver="white.sys-1",
        scope=SCOPE, ttl_seconds=3600, author="silver.build-1", approver_role="platform-owner",
    )
    security = gov.record_approval(task["task_id"], gated_action="release",
                                   approver="black.diag-1", scope=SCOPE,
                                   author="silver.build-1", approver_role="security-lead")
    approval = platform
    assert gov.approval_valid(approval.approval_id, task["task_id"], "release", SCOPE)
    assert not gov.approval_valid(approval.approval_id, task["task_id"], "rollback", SCOPE)
    assert not gov.approval_valid(approval.approval_id, task["task_id"], "release",
                                  SCOPE, now_epoch=float("inf"))
    assert not gov.approval_valid(approval.approval_id, task["task_id"], "release",
                                  {"environments": ["production"]})
    assert gov.has_valid_approval(task["task_id"], "release", requested_scope=SCOPE)


def test_expired_approval_invalid(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    expired = gov.record_approval(
        task["task_id"], gated_action="release", approver="white.sys-1",
        scope=SCOPE, ttl_seconds=-60, author="silver.build-1",
    )
    assert not gov.approval_valid(expired.approval_id, task["task_id"], "release", SCOPE)


def test_revoked_approval_invalid(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    approval = gov.record_approval(
        task["task_id"], gated_action="release", approver="white.sys-1", scope=SCOPE, author="silver.build-1",
    )
    gov.revoke_approval(approval.approval_id, actor="white.sys-1", reason="scope drift")
    assert not gov.has_valid_approval(task["task_id"], "release", requested_scope=SCOPE)


# ---------------------------------------------------------------------------
# Coordinator gating (acceptance: missing approval blocks protected actions)
# ---------------------------------------------------------------------------

def test_missing_approval_blocks_release(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    _drive_to(c, task["task_id"], TaskState.APPROVE)
    blocked = c.apply_transition(
        task["task_id"], Trigger.RELEASE_APPROVED, actor=Coordinator.SYSTEM_AGENT,
        reason="release", evidence_refs=("log://rel",), request_id="rid-rel-no-apr",
    )
    assert blocked["success"] is False
    assert blocked["error"]["code"] == RejectionCode.APPROVAL_MISSING.value
    assert c.get_task(task["task_id"])["state"] == TaskState.APPROVE.value

    gov.record_approval(
        task["task_id"], gated_action="release", approver="white.sys-1", scope=SCOPE, author="silver.build-1",
        approver_role="platform-owner",
    )
    security = gov.record_approval(task["task_id"], gated_action="release", approver="black.diag-1",
                                   scope=SCOPE, author="silver.build-1", approver_role="security-lead")
    ok = c.apply_transition(
        task["task_id"], Trigger.RELEASE_APPROVED, actor=Coordinator.SYSTEM_AGENT,
        reason="release", evidence_refs=(security.evidence_id,), request_id="rid-rel-apr",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.RELEASE.value


def test_rollback_requires_approval(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    _drive_to(c, task["task_id"], TaskState.APPROVE)
    gov.record_approval(task["task_id"], gated_action="release", approver="white.sys-1", scope=SCOPE, author="silver.build-1", approver_role="platform-owner")
    rel_security = gov.record_approval(task["task_id"], gated_action="release", approver="black.diag-1", scope=SCOPE, author="silver.build-1", approver_role="security-lead")
    c.apply_transition(task["task_id"], Trigger.RELEASE_APPROVED, actor=Coordinator.SYSTEM_AGENT,
                       reason="release", evidence_refs=(rel_security.evidence_id,), request_id="rid-rel")
    blocked = c.apply_transition(
        task["task_id"], Trigger.ROLLBACK_INITIATED, actor="green.rel-1",
        reason="rollback", evidence_refs=("log://rb",), request_id="rid-rb-no-apr",
    )
    assert blocked["error"]["code"] == RejectionCode.APPROVAL_MISSING.value
    gov.record_approval(task["task_id"], gated_action="rollback", approver="white.sys-1", scope=SCOPE, author="green.rel-1", approver_role="platform-owner")
    rb_security = gov.record_approval(task["task_id"], gated_action="rollback", approver="black.diag-1", scope=SCOPE, author="green.rel-1", approver_role="security-lead")
    ok = c.apply_transition(
        task["task_id"], Trigger.ROLLBACK_INITIATED, actor="green.rel-1",
        reason="rollback", evidence_refs=(rb_security.evidence_id,), request_id="rid-rb-apr",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.ROLLED_BACK.value


# ---------------------------------------------------------------------------
# Pause / escalation
# ---------------------------------------------------------------------------

def test_pause_blocks_progression_until_resume(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    _drive_to(c, task["task_id"], TaskState.BUILD)
    gov.pause(task["task_id"], actor="white.sys-1", reason="evidence insufficient")
    blocked = c.apply_transition(
        task["task_id"], Trigger.IMPLEMENTATION_READY, actor="silver.build-1",
        reason="ready", evidence_refs=("log://ready",), request_id="rid-ready-paused",
    )
    assert blocked["error"]["code"] == RejectionCode.PAUSED.value
    assert c.get_task(task["task_id"])["state"] == TaskState.BUILD.value

    gov.resume(task["task_id"], actor="white.sys-1", reason="resolved")
    change_refs = _record_gate_evidence(c, task["task_id"], Trigger.IMPLEMENTATION_READY)
    ok = c.apply_transition(
        task["task_id"], Trigger.IMPLEMENTATION_READY, actor="silver.build-1",
        reason="ready", evidence_refs=change_refs, request_id="rid-ready-ok",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.VERIFY.value


def test_escalation_recorded(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    _drive_to(c, task["task_id"], TaskState.BUILD)
    gov.escalate(task["task_id"], actor="silver.build-1", reason="needs authority",
                 decision_ref=f"task://{task['task_id']}")
    decisions = [r for r in gov.ledger.records if r.record_type == "decision"]
    assert decisions and decisions[-1].payload["decision_type"] == "escalation"


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

def test_risk_increase_only(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE, risk="yellow")
    raised = gov.raise_risk(task["task_id"], risk="orange", actor="white.sys-1",
                            reason="blast radius grew")
    assert raised == RiskClass.ORANGE
    with pytest.raises(RiskRegressionError):
        gov.raise_risk(task["task_id"], risk="yellow", actor="white.sys-1", reason="nope")
    assert gov.current_risk(task["task_id"]) == RiskClass.ORANGE


# ---------------------------------------------------------------------------
# Evidence ledger
# ---------------------------------------------------------------------------

def test_incomplete_evidence_cannot_be_marked_complete(tmp_path) -> None:
    ledger = EvidenceLedger(path=str(tmp_path / "l1.jsonl"))
    draft = ledger.append(
        "approval", status="draft", actor="x", team="white",
        source="test://", payload={}, task_id="task-1",
    )
    with pytest.raises(IncompleteEvidenceError):
        ledger.mark_complete(draft.evidence_id)
    completed = ledger.complete_evidence(
        draft.evidence_id,
        extra_payload={
            "approver": "white.sys-1", "scope": SCOPE, "expiry": "2026-09-19T00:00:00.000Z",
            "gated_action": "release", "decision_id": "dec-1", "approval_id": "apr-test",
        },
        actor="white.sys-1", team="white", source="test://complete",
    )
    assert completed.status == "complete"
    assert draft.evidence_id in completed.refs
    assert ledger.get(draft.evidence_id).status == "draft"


def test_completed_record_immutable(tmp_path) -> None:
    ledger = EvidenceLedger()
    done = ledger.append(
        "observation", actor="observer.ro-1", team="observer", source="test://",
        payload={"observation_type": "health", "detail": "ok"},
    )
    with pytest.raises(LedgerImmutableError):
        ledger.mark_complete(done.evidence_id)
    with pytest.raises(LedgerImmutableError):
        ledger.complete_evidence(done.evidence_id, extra_payload={},
                                 actor="y", team="white", source="test://")


def test_ledger_hash_chain_detects_tampering(tmp_path) -> None:
    ledger = EvidenceLedger(path=str(tmp_path / "l3.jsonl"))
    for i in range(3):
        ledger.append("observation", actor="a", team="observer", source="test://",
                      payload={"observation_type": "metric", "detail": f"m{i}"},
                      task_id=f"task-{i}")
    assert ledger.verify_chain()
    tampered = ledger.records[1]
    object.__setattr__(tampered, "payload", {"observation_type": "metric", "detail": "tampered"})
    assert not ledger.verify_chain()


# ---------------------------------------------------------------------------
# Audit + ledger integration
# ---------------------------------------------------------------------------

def test_transitions_land_in_ledger(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    drive_full_path(c, task["task_id"])
    transitions = [r for r in gov.ledger.records if r.record_type == "transition"]
    assert len(transitions) == len(FULL_PATH)
    assert all(r.payload["trigger"] for r in transitions)


def test_audit_output_is_append_only(tmp_path) -> None:
    c, gov, _ = make_governed(tmp_path)
    task = c.create_task(title="t", scope=SCOPE)
    _drive_to(c, task["task_id"], TaskState.APPROVE)
    gov.record_approval(task["task_id"], gated_action="release", approver="white.sys-1", scope=SCOPE, author="silver.build-1")
    audit_path = str(tmp_path / "audit.jsonl")
    gov.write_audit(audit_path)
    with open(audit_path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    assert len(lines) == len(gov.audit_entries())
    assert all(r["status"] == "complete" for r in lines)
    assert gov.ledger.verify_chain()


def test_restart_rebuilds_governance_state(tmp_path) -> None:
    reg = make_registry()
    c1, gov1, _ = make_governed(tmp_path, registry=reg)
    task = c1.create_task(title="t", scope=SCOPE)
    _drive_to(c1, task["task_id"], TaskState.APPROVE)
    approval = gov1.record_approval(
        task["task_id"], gated_action="release", approver="white.sys-1", scope=SCOPE,
        author="silver.build-1", approver_role="platform-owner",
    )
    gov1.record_approval(task["task_id"], gated_action="release", approver="black.diag-1",
                         scope=SCOPE, author="silver.build-1", approver_role="security-lead")
    gov1.pause(task["task_id"], actor="white.sys-1", reason="review")

    ledger_path = str(tmp_path / "ledger.jsonl")
    gov2 = WhiteTeam(registry=reg, ledger_path=ledger_path)
    c2 = Coordinator(registry=reg, store_path=str(tmp_path / "events.jsonl"), governance=gov2)
    assert c2.get_task(task["task_id"])["state"] == TaskState.APPROVE.value
    assert gov2.has_valid_approval(task["task_id"], "release", requested_scope=SCOPE)
    assert gov2.approval_valid(approval.approval_id, task["task_id"], "release", SCOPE)
    assert gov2.is_paused(task["task_id"])
