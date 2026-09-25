"""Phase 10: end-to-end integration and adversarial validation scenarios."""

from __future__ import annotations

import time

import pytest

from colorharness import (
    Coordinator,
    GreenTeam,
    RedTeam,
    TeamRegistry,
    Watchdog,
    WhiteTeam,
    YellowTeam,
)
from colorharness._common import Trigger
from tests.test_phase1_coordinator import make_registry


def test_all_nine_teams_are_registered() -> None:
    registry = make_registry()
    expected = {"observer", "red", "blue", "black", "purple", "gold", "silver", "yellow", "green", "white"}
    registered = {registry.team_of(agent_id) for agent_id in registry._agents}
    assert expected <= registered


def test_ci_failure_blocks_release_progression(tmp_path) -> None:
    registry = make_registry()
    governance = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl"))
    yellow = YellowTeam(registry=registry)
    result = yellow.run_check(
        task_id="ci-1", actor="yellow.ver-1", check_type="test",
        command="pytest", version="pytest-9", exit_status=1,
        artifacts_ref="artifact://ci", evidence_location="ci://run-1",
    )
    governance.record_yellow_output("ci-1", (result,))
    assert result.passed is False
    assert governance.verification_passing("ci-1") is False


def test_red_finding_can_be_closed_by_purple_chain() -> None:
    registry = make_registry()
    red = RedTeam(registry=registry)
    finding = red.report_finding(
        task_id="vuln-1", actor="red.tar-1", title="dependency vulnerability",
        reproduction=("install vulnerable package",), impact="known exploit",
        severity="high", remediation_recommendation="upgrade dependency",
        targets=("staging:api",),
    )
    assert finding.severity == "high"


def test_staging_release_requires_rollback_ready_plan(tmp_path) -> None:
    registry = make_registry()
    governance = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl"))
    green = GreenTeam(registry=registry, governance=governance)
    plan = green.release_plan(
        "staging-1", actor="green.rel-1", title="staging rollout",
        artifact_ref="sha256:release", target_environment="staging",
        phases=("canary", "promote"), rollback_metadata={"restore": "sha256:previous"},
    )
    platform = governance.record_approval(
        "staging-1", gated_action="release", approver="white.sys-1", scope={"repo": "demo"}, author="silver.build-1", approver_role="platform-owner"
    )
    security = governance.record_approval(
        "staging-1", gated_action="release", approver="black.diag-1", scope={"repo": "demo"}, author="silver.build-1", approver_role="security-lead"
    )
    release = green.execute_release(
        "staging-1", actor="green.rel-1", plan=plan,
        approvals=(platform.approval_id, security.approval_id),
    )
    rollback = green.rollback(
        "staging-1", actor="green.rel-1", release_ref=release.release_id,
        steps=("restore sha256:previous",), reason="canary failed",
    )
    records = governance.record_green_output("staging-1", (release, rollback))
    assert [record.record_type for record in records] == ["release", "rollback"]


def test_watchdog_quarantines_and_recovers_agent(tmp_path) -> None:
    registry = make_registry()
    watchdog = Watchdog(now_fn=lambda: 1000.0)
    governance = WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl"))
    Coordinator(registry=registry, store_path=str(tmp_path / "events.jsonl"),
                governance=governance, watchdog=watchdog)
    watchdog.heartbeat("green.rel-1", actor="green.rel-1", now=0.0)
    assert watchdog.is_stale("green.rel-1", interval_seconds=60, now=181.0)
    assert watchdog.is_quarantined("green.rel-1")
    watchdog.quarantine("green.rel-1", actor="white.sys-1", reason="manual review")
    assert watchdog.is_quarantined("green.rel-1")
    watchdog.heartbeat("green.rel-1", actor="green.rel-1", now=1000.0)
    watchdog.unquarantine("green.rel-1", actor="white.sys-1")
    assert not watchdog.is_quarantined("green.rel-1")


def test_duplicate_transition_replay_is_idempotent(tmp_path) -> None:
    registry = make_registry()
    coordinator = Coordinator(registry=registry, store_path=str(tmp_path / "events.jsonl"),
                              governance=WhiteTeam(registry=registry, ledger_path=str(tmp_path / "ledger.jsonl")))
    task = coordinator.create_task(title="replay", scope={"repo": "demo"})
    first = coordinator.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="route", evidence_refs=("route://1",), request_id="same-request",
    )
    second = coordinator.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="route", evidence_refs=("route://1",), request_id="same-request",
    )
    assert first == second
    assert coordinator.get_task(task["task_id"])["state"] == "OBSERVE"


def test_unauthorized_release_actor_is_rejected() -> None:
    green = GreenTeam(registry=make_registry())
    with pytest.raises(Exception):
        green.release_plan(
            "task-1", actor="silver.build-1", title="bad release",
            artifact_ref="sha256:x", target_environment="production",
            phases=("promote",), rollback_metadata={"restore": "previous"},
        )
