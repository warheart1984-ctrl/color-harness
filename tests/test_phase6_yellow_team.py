"""Phase 6 acceptance checks: Yellow Team verification — independent test
results with command/version/status/evidence location, no self-approval, and
the coordinator's VERIFICATION_PASSED gate (recorded evidence, failures block)."""

from __future__ import annotations

import pytest

from colorharness import (
    BlackTeam,
    Coordinator,
    InvalidCheckError,
    Observer,
    SelfApprovalError,
    SilverTeam,
    TeamRegistry,
    VerificationResult,
    WhiteTeam,
    YellowNoEvidenceError,
    YellowTeam,
    YellowUnauthorizedActorError,
)
from colorharness._common import RejectionCode, TaskState, Trigger
from tests.test_phase1_coordinator import make_registry

DEV = {"ci_cd": {"environments": ["staging"]}, "repo": "color-harness"}


def make_yellow(reg: TeamRegistry | None = None) -> YellowTeam:
    return YellowTeam(registry=reg or make_registry())


def run_ok(yellow: YellowTeam, task_id: str, check_type: str = "readiness") -> VerificationResult:
    return yellow.run_check(
        task_id=task_id, actor="yellow.ver-1",
        check_type=check_type, command="pytest -q", version="pytest 9.1.1",
        exit_status=0, artifacts_ref="artifacts://run",
        evidence_location="report://run",
    )


# ---------------------------------------------------------------------------
# Yellow Team unit behavior
# ---------------------------------------------------------------------------

def test_run_check_valid() -> None:
    result = make_yellow().run_check(
        task_id="task-1", actor="yellow.ver-1",
        check_type="test", command="pytest -q", version="pytest 9.1.1",
        exit_status=0, artifacts_ref="artifacts://1",
        evidence_location="report://1",
    )
    assert isinstance(result, VerificationResult)
    assert result.passed is True
    assert result.command == "pytest -q"
    assert result.version == "pytest 9.1.1"


def test_run_check_failed_status_recorded() -> None:
    result = run_ok(make_yellow(), "task-1")
    assert result.exit_status == 0
    failed = make_yellow().run_check(
        task_id="task-1", actor="yellow.ver-1",
        check_type="lint", command="ruff check", version="ruff 0.9",
        exit_status=1, artifacts_ref="artifacts://2",
        evidence_location="report://2",
    )
    assert failed.passed is False


def test_check_rejects_unknown_type_and_empty_fields() -> None:
    yellow = make_yellow()
    with pytest.raises(InvalidCheckError):
        yellow.run_check(task_id="task-1", actor="yellow.ver-1",
                         check_type="magic", command="x", version="1",
                         exit_status=0, artifacts_ref="a", evidence_location="e")
    with pytest.raises(YellowNoEvidenceError):
        yellow.run_check(task_id="task-1", actor="yellow.ver-1",
                         check_type="test", command="x", version="",
                         exit_status=0, artifacts_ref="a", evidence_location="e")
    with pytest.raises(YellowNoEvidenceError):
        yellow.run_check(task_id="task-1", actor="yellow.ver-1",
                         check_type="test", command="x", version="1",
                         exit_status=0, artifacts_ref="", evidence_location="e")


def test_yellow_requires_yellow_actor() -> None:
    yellow = make_yellow()
    with pytest.raises(YellowUnauthorizedActorError):
        yellow.run_check(task_id="task-1", actor="silver.build-1",
                         check_type="test", command="x", version="1",
                         exit_status=0, artifacts_ref="a", evidence_location="e")
    with pytest.raises(YellowUnauthorizedActorError):
        yellow.run_check(task_id="task-1", actor="ghost.1",
                         check_type="test", command="x", version="1",
                         exit_status=0, artifacts_ref="a", evidence_location="e")


def test_yellow_cannot_approve_own_implementation() -> None:
    reg = make_registry()
    assert not reg.has_role("yellow.ver-1", "ci-operator")
    with pytest.raises(Exception):
        reg.grant_role("yellow.ver-1", "security-lead")
    with pytest.raises(SelfApprovalError):
        reg.grant_role("yellow.ver-1", "ci-operator")
        YellowTeam(registry=reg).forbid_self_approval("yellow.ver-1")
    assert reg.has_role("yellow.ver-1", "ci-operator")


def test_yellow_forbid_self_approval_triggers_on_ci_operator() -> None:
    reg = make_registry()
    reg.grant_role("yellow.ver-1", "ci-operator")
    with pytest.raises(SelfApprovalError):
        YellowTeam(registry=reg).forbid_self_approval("yellow.ver-1")


# ---------------------------------------------------------------------------
# White records verification results as evidence
# ---------------------------------------------------------------------------

def test_white_records_yellow_output(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    result = run_ok(make_yellow(), "task-1")
    records = gov.record_yellow_output("task-1", (result,))
    assert len(records) == 1
    record = records[0]
    assert record.record_type == "test_result"
    assert record.payload["exit_status"] == 0
    assert record.payload["evidence_location"] == "report://run"
    assert tuple(record.refs) == ("artifacts://run",)
    assert gov.ledger.verify_chain()


def test_verification_passing_semantics(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    yellow = make_yellow()
    assert not gov.verification_passing("task-1")
    gov.record_yellow_output("task-1", (run_ok(yellow, "task-1"),))
    assert gov.verification_passing("task-1")
    failed = yellow.run_check(task_id="task-1", actor="yellow.ver-1",
                              check_type="policy", command="check", version="1",
                              exit_status=1, artifacts_ref="a",
                              evidence_location="e")
    gov.record_yellow_output("task-1", (failed,))
    assert not gov.verification_passing("task-1")
    assert gov.has_evidence("task-1", "test_result")


# ---------------------------------------------------------------------------
# Coordinator gate: VERIFICATION_PASSED requires passing recorded results
# ---------------------------------------------------------------------------

def _drive_to_verify(c: Coordinator, task_id: str) -> None:
    c.apply_transition(task_id, Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("log://route",), request_id="r-route")
    obs = Observer().collect(task_id=task_id, observation_type="ci",
                             detail={"pipeline": "build", "exit_status": 1})
    c.governance.record_observations(task_id, (obs,))
    c.apply_transition(task_id, Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
                       reason="obs", evidence_refs=("log://obs",), request_id="r-obs")
    diag = BlackTeam(registry=c.registry).diagnose(
        task_id=task_id, actor="black.diag-1",
        diagnosis="deploy agent timeout", confidence="medium",
        evidence_refs=(obs.observation_id,), alternatives=("rate limit",),
    )
    c.governance.record_black_output(task_id, (diag,))
    c.apply_transition(task_id, Trigger.DIAGNOSIS_ACCEPTED, actor="black.diag-1",
                       reason="diag", evidence_refs=("log://diag",), request_id="r-diag")
    c.apply_transition(task_id, Trigger.PLAN_APPROVED, actor="gold.plan-1",
                       reason="plan", evidence_refs=("log://plan",), request_id="r-plan")
    manifest = SilverTeam(registry=c.registry).present_change(
        task_id=task_id, actor="silver.build-1",
        change_type="branch", branch="isolated/svc-timeout",
        files=("deploy.yaml",), diff_summary="raise timeout",
        plan_refs=("log://plan",), rollback_metadata={"steps": ["git revert"]},
    )
    c.governance.record_silver_output(task_id, (manifest,))
    c.apply_transition(task_id, Trigger.IMPLEMENTATION_READY, actor="silver.build-1",
                       reason="impl", evidence_refs=("log://impl",), request_id="r-impl")


def test_verification_passed_gated_on_recorded_results(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="orange")
    _drive_to_verify(c, task["task_id"])
    assert c.get_task(task["task_id"])["state"] == TaskState.VERIFY.value

    blocked = c.apply_transition(
        task["task_id"], Trigger.VERIFICATION_PASSED, actor="yellow.ver-1",
        reason="verify", evidence_refs=("log://verify",), request_id="r-verify",
    )
    assert blocked["success"] is False
    assert blocked["error"]["code"] == RejectionCode.EVIDENCE_NOT_RECORDED.value

    gov.record_yellow_output(task["task_id"],
                             (run_ok(make_yellow(reg), task["task_id"]),))
    ok = c.apply_transition(
        task["task_id"], Trigger.VERIFICATION_PASSED, actor="yellow.ver-1",
        reason="verify", evidence_refs=("log://verify",), request_id="r-verify2",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.APPROVE.value


def test_failed_check_blocks_verification_passed(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="orange")
    _drive_to_verify(c, task["task_id"])

    yellow = make_yellow(reg)
    failed = yellow.run_check(task_id=task["task_id"], actor="yellow.ver-1",
                              check_type="policy", command="check", version="1",
                              exit_status=1, artifacts_ref="a",
                              evidence_location="e")
    gov.record_yellow_output(task["task_id"], (failed,))
    blocked = c.apply_transition(
        task["task_id"], Trigger.VERIFICATION_PASSED, actor="yellow.ver-1",
        reason="verify", evidence_refs=("log://verify",), request_id="r-verify",
    )
    assert blocked["success"] is False
    assert blocked["error"]["code"] == RejectionCode.VERIFICATION_FAILED.value
    assert c.get_task(task["task_id"])["state"] == TaskState.VERIFY.value


# ---------------------------------------------------------------------------
# Full chain: observe -> ... -> verified
# ---------------------------------------------------------------------------

def test_observe_to_verification_chain(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="yellow")
    _drive_to_verify(c, task["task_id"])

    yellow = make_yellow(reg)
    gov.record_yellow_output(task["task_id"], (
        yellow.run_check(task_id=task["task_id"], actor="yellow.ver-1",
                         check_type="test", command="pytest -q",
                         version="pytest 9.1.1", exit_status=0,
                         artifacts_ref="artifacts://1", evidence_location="report://1"),
        yellow.run_check(task_id=task["task_id"], actor="yellow.ver-1",
                         check_type="readiness", command="readiness",
                         version="check 1.0", exit_status=0,
                         artifacts_ref="artifacts://2", evidence_location="report://2"),
    ))
    ok = c.apply_transition(task["task_id"], Trigger.VERIFICATION_PASSED,
                            actor="yellow.ver-1", reason="all green",
                            evidence_refs=("log://verify",), request_id="r-verify")
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.APPROVE.value

    records = {r.record_type for r in gov.ledger.records}
    assert {"observation", "diagnosis", "change", "test_result"} <= records
    results = [r for r in gov.ledger.records if r.record_type == "test_result"]
    assert all(r.payload["exit_status"] == 0 for r in results)
    assert all(r.payload["version"] for r in results)
    assert all(r.payload["evidence_location"] for r in results)
    assert gov.ledger.verify_chain()
    assert gov.ledger.verify_manifest()