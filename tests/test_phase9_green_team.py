"""Phase 9 acceptance checks: Green Team release and rollback operations."""

from __future__ import annotations

import time

import pytest

from colorharness import (
    GreenReleaseNotApproved,
    GreenRollbackPlanRequired,
    GreenTeam,
    Release,
    ReleasePlan,
    Rollback,
    WhiteTeam,
)
from tests.test_phase1_coordinator import make_registry


def test_release_plan_requires_rollback() -> None:
    green = GreenTeam(registry=make_registry())
    with pytest.raises(GreenRollbackPlanRequired):
        green.release_plan(
            "task-1", actor="green.rel-1", title="deploy", artifact_ref="sha256:x",
            target_environment="staging", phases=("canary",), rollback_metadata={},
        )


def test_release_requires_recorded_approval(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl"))
    green = GreenTeam(registry=reg, governance=gov)
    plan = green.release_plan(
        "task-1", actor="green.rel-1", title="deploy", artifact_ref="sha256:x",
        target_environment="staging", phases=("canary", "promote"),
        rollback_metadata={"steps": "redeploy previous digest"},
    )
    with pytest.raises(GreenReleaseNotApproved):
        green.execute_release("task-1", actor="green.rel-1", plan=plan, approvals=())

    approval = gov.record_approval(
        "task-1", gated_action="release", approver="white.sys-1", scope={"repo": "demo"}
    )
    release = green.execute_release(
        "task-1", actor="green.rel-1", plan=plan, approvals=(approval.approval_id,)
    )
    assert isinstance(release, Release)
    assert release.approval_refs == (approval.approval_id,)


def test_white_records_release_and_rollback(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl"))
    green = GreenTeam(registry=reg)
    plan = green.release_plan(
        "task-1", actor="green.rel-1", title="deploy", artifact_ref="sha256:x",
        target_environment="staging", phases=("canary",),
        rollback_metadata={"steps": "restore previous"},
    )
    approval = "approval-release-1"
    release = Release(
        release_id="rel-1", task_id="task-1", actor="green.rel-1",
        artifact_ref=plan.artifact_ref, target_environment=plan.target_environment,
        plan_ref=plan.plan_id, approval_refs=(approval,), timestamp=plan.timestamp,
    )
    rollback = green.rollback(
        "task-1", actor="green.rel-1", release_ref=release.release_id,
        steps=("restore previous",), reason="canary degraded",
    )
    records = gov.record_green_output("task-1", (release, rollback))
    assert [record.record_type for record in records] == ["release", "rollback"]
    assert gov.ledger.verify_chain()
    assert gov.ledger.verify_manifest()

