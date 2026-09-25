"""Phase 5 acceptance checks: Silver Team implementation — attributable change
manifests with rollback metadata, secrets never logged, no merge/deploy, and
the coordinator's IMPLEMENTATION_READY evidence gate."""

from __future__ import annotations

import pytest

from colorharness import (
    BlackTeam,
    ChangeManifest,
    Coordinator,
    InvalidImplementationError,
    Observer,
    SecretInImplementationError,
    SilverNoEvidenceError,
    SilverTeam,
    SilverUnauthorizedActorError,
    TeamRegistry,
    WhiteTeam,
)
from colorharness._common import RejectionCode, TaskState, Trigger
from colorharness.registry import TEAM_CHARTER
from tests.test_phase1_coordinator import FULL_PATH, _record_gate_evidence, make_registry

DEV = {"ci_cd": {"environments": ["staging"]}, "repo": "color-harness"}


def make_silver(reg: TeamRegistry | None = None) -> SilverTeam:
    return SilverTeam(registry=reg or make_registry())


def rollback_meta() -> dict:
    return {"steps": ["git revert <sha>", "restore config from backup"]}


# ---------------------------------------------------------------------------
# Silver Team unit behavior
# ---------------------------------------------------------------------------

def test_present_change_valid() -> None:
    manifest = make_silver().present_change(
        task_id="task-1", actor="silver.build-1",
        change_type="branch", branch="isolated/svc-timeout",
        files=("app/deploy.yaml", "app/service.py"),
        diff_summary="raise deploy agent timeout",
        plan_refs=("dec-plan-1", "diag-1"),
        rollback_metadata={"steps": ["git revert <sha>"]},
        resources=("pipeline:build",),
        configurations=("deploy.yaml",),
        approval_scope={"environments": ["staging"]},
    )
    assert isinstance(manifest, ChangeManifest)
    assert manifest.plan_refs == ("dec-plan-1", "diag-1")
    assert manifest.approval_scope == {"environments": ["staging"]}
    assert manifest.rollback_metadata["steps"]


def test_change_requires_plan_evidence() -> None:
    with pytest.raises(SilverNoEvidenceError):
        make_silver().present_change(
            task_id="task-1", actor="silver.build-1",
            change_type="branch", branch="b", files=("f",),
            diff_summary="d", plan_refs=(),
            rollback_metadata={"steps": ["git revert"]},
        )


def test_change_rejects_unsupported_type() -> None:
    with pytest.raises(InvalidImplementationError):
        make_silver().present_change(
            task_id="task-1", actor="silver.build-1",
            change_type="tooling", branch="b", files=("f",),
            diff_summary="d", plan_refs=("plan-1",),
            rollback_metadata={"steps": ["git revert"]},
        )


def test_change_requires_files_and_rollback() -> None:
    silver = make_silver()
    with pytest.raises(InvalidImplementationError):
        silver.present_change(
            task_id="task-1", actor="silver.build-1",
            change_type="branch", branch="b", files=(),
            diff_summary="d", plan_refs=("plan-1",),
            rollback_metadata={"steps": ["git revert"]},
        )
    with pytest.raises(InvalidImplementationError):
        silver.present_change(
            task_id="task-1", actor="silver.build-1",
            change_type="branch", branch="b", files=("f",),
            diff_summary="d", plan_refs=("plan-1",),
            rollback_metadata={},
        )


def test_change_rejects_secrets_never_logged() -> None:
    with pytest.raises(SecretInImplementationError):
        make_silver().present_change(
            task_id="task-1", actor="silver.build-1",
            change_type="branch", branch="b", files=("f",),
            diff_summary="gs_token sk_live_abcdef1234567890 landed in trace",
            plan_refs=("plan-1",),
            rollback_metadata={"steps": ["git revert"]},
        )
    with pytest.raises(SecretInImplementationError):
        make_silver().present_change(
            task_id="task-1", actor="silver.build-1",
            change_type="config", branch="b", files=("f",),
            diff_summary="d", plan_refs=("plan-1",),
            rollback_metadata={"steps": ["git revert"], "pwd": "-----BEGIN RSA PRIVATE KEY-----"},
        )


def test_silver_requires_silver_actor() -> None:
    silver = make_silver()
    with pytest.raises(SilverUnauthorizedActorError):
        silver.present_change(
            task_id="task-1", actor=Coordinator.SYSTEM_AGENT,
            change_type="branch", branch="b", files=("f",),
            diff_summary="d", plan_refs=("plan-1",),
            rollback_metadata={"steps": ["git revert"]},
        )
    with pytest.raises(SilverUnauthorizedActorError):
        silver.present_change(
            task_id="task-1", actor="ghost.1",
            change_type="branch", branch="b", files=("f",),
            diff_summary="d", plan_refs=("plan-1",),
            rollback_metadata={"steps": ["git revert"]},
        )


def test_silver_cannot_merge_or_deploy() -> None:
    silver = make_silver()
    assert not hasattr(silver, "merge")
    assert not hasattr(silver, "deploy")
    caps = TEAM_CHARTER["silver"]
    assert not ({"merge", "deploy", "release"} & caps)


# ---------------------------------------------------------------------------
# White records change manifests as evidence
# ---------------------------------------------------------------------------

def test_white_records_change_evidence(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    plan = gov.record_approval("task-1", gated_action="plan_approval",
                               approver="white.sys-1", scope=DEV,
                               author="silver.build-1", approver_role="ci-operator")
    manifest = make_silver().present_change(
        task_id="task-1", actor="silver.build-1",
        change_type="config", branch="isolated/svc-timeout",
        files=("deploy.yaml",), diff_summary="raise timeout",
        plan_refs=(plan.evidence_id,), rollback_metadata=rollback_meta(),
    )
    records = gov.record_silver_output("task-1", (manifest,))
    assert len(records) == 1
    record = records[0]
    assert record.record_type == "change"
    assert record.task_id == "task-1"
    assert record.payload["change_type"] == "config"
    assert record.payload["plan_refs"] == [plan.evidence_id]
    assert (plan.evidence_id,) == tuple(record.refs)
    assert gov.ledger.verify_chain()


def test_white_records_change_rejects_secret(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    secret_bearer = object.__new__(ChangeManifest)
    from colorharness._common import now_utc_iso
    object.__setattr__(secret_bearer, "manifest_id", "chg-evil")
    object.__setattr__(secret_bearer, "task_id", "task-1")
    object.__setattr__(secret_bearer, "actor", "silver.build-1")
    object.__setattr__(secret_bearer, "change_type", "config")
    object.__setattr__(secret_bearer, "branch", "b")
    object.__setattr__(secret_bearer, "files", ("f",))
    object.__setattr__(secret_bearer, "diff_summary", "AKIA0123456789ABCDEF leaked")
    object.__setattr__(secret_bearer, "resources", ())
    object.__setattr__(secret_bearer, "configurations", ())
    object.__setattr__(secret_bearer, "approval_scope", {})
    object.__setattr__(secret_bearer, "plan_refs", ("plan-1",))
    object.__setattr__(secret_bearer, "rollback_metadata", {"steps": ["git revert"]})
    object.__setattr__(secret_bearer, "timestamp", now_utc_iso())
    with pytest.raises(Exception):
        gov.record_silver_output("task-1", (secret_bearer,))
    assert len(gov.ledger) == 0


# ---------------------------------------------------------------------------
# Coordinator gate: IMPLEMENTATION_READY requires recorded change evidence
# ---------------------------------------------------------------------------

def _drive_to_plan(c: Coordinator, task_id: str) -> None:
    for trigger, actor, reason in FULL_PATH:
        refs = _record_gate_evidence(c, task_id, trigger)
        result = c.apply_transition(task_id, trigger, actor=actor, reason=reason,
                                    evidence_refs=refs or (f"log://{reason}",),
                                    request_id=f"rid-{reason}")
        assert result["success"], result.get("error")
        if result["event"]["to_state"] == TaskState.BUILD.value:
            return


def test_implementation_ready_gated_on_recorded_change(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="orange")
    _drive_to_plan(c, task["task_id"])
    assert c.get_task(task["task_id"])["state"] == TaskState.BUILD.value

    blocked = c.apply_transition(
        task["task_id"], Trigger.IMPLEMENTATION_READY, actor="silver.build-1",
        reason="impl", evidence_refs=("log://impl",), request_id="r-impl",
    )
    assert blocked["success"] is False
    assert blocked["error"]["code"] == RejectionCode.EVIDENCE_NOT_RECORDED.value
    assert c.get_task(task["task_id"])["state"] == TaskState.BUILD.value

    manifest = make_silver(reg).present_change(
        task_id=task["task_id"], actor="silver.build-1",
        change_type="branch", branch="isolated/svc-timeout",
        files=("deploy.yaml",), diff_summary="raise timeout",
        plan_refs=(next(r.evidence_id for r in reversed(gov.ledger.records)
                       if r.task_id == task["task_id"] and r.record_type == "approval"
                       and r.payload.get("gated_action") == "plan_approval"),),
        rollback_metadata=rollback_meta(),
    )
    change_record = gov.record_silver_output(task["task_id"], (manifest,))[0]
    ok = c.apply_transition(
        task["task_id"], Trigger.IMPLEMENTATION_READY, actor="silver.build-1",
        reason="impl", evidence_refs=(change_record.evidence_id,), request_id="r-impl2",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.VERIFY.value


def test_implementation_gate_requires_white(tmp_path) -> None:
    import pytest
    reg = make_registry()
    with pytest.raises(ValueError):
        Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=None)


# ---------------------------------------------------------------------------
# Full chain: observe -> diagnose -> plan -> implement -> ready
# ---------------------------------------------------------------------------

def test_observe_to_implementation_chain(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="yellow")
    _drive_to_plan(c, task["task_id"])

    manifest = make_silver(reg).present_change(
        task_id=task["task_id"], actor="silver.build-1",
        change_type="branch", branch="isolated/svc-timeout",
        files=("deploy.yaml", "service.py"),
        diff_summary="raise deploy agent timeout from 30s to 90s",
        plan_refs=(next(r.evidence_id for r in reversed(gov.ledger.records)
                       if r.task_id == task["task_id"] and r.record_type == "approval"
                       and r.payload.get("gated_action") == "plan_approval"),),
        rollback_metadata={"steps": ["git revert <sha>"], "owner": "release-ops"},
        resources=("pipeline:build",),
        configurations=("deploy.yaml",),
        approval_scope=DEV,
    )
    change_record = gov.record_silver_output(task["task_id"], (manifest,))[0]
    ok = c.apply_transition(
        task["task_id"], Trigger.IMPLEMENTATION_READY, actor="silver.build-1",
        reason="implementation ready", evidence_refs=(change_record.evidence_id,),
        request_id="r-impl",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.VERIFY.value

    records = {r.record_type for r in gov.ledger.records}
    assert {"observation", "diagnosis", "change"} <= records
    change = [r for r in gov.ledger.records if r.record_type == "change"][0]
    assert change.payload["rollback_metadata"]["steps"] == ["git revert <sha>"]
    assert change.payload["approval_scope"] == DEV
    assert gov.ledger.verify_chain()
    assert not gov.ledger.verify_manifest()
