"""Phase 7 acceptance checks: Red Team (authorized adversarial testing —
findings complete, unspecified/destructive refused) and Purple Team (closure
validation — closure requires re-test evidence)."""

from __future__ import annotations

import pytest

from colorharness import (
    Closure,
    Coordinator,
    Finding,
    InvalidClosureError,
    InvalidFindingError,
    PurpleNoReTestError,
    PurpleTeam,
    PurpleUnauthorizedActorError,
    RedDestructiveTestRefusedError,
    RedTeam,
    RedUnauthorizedActorError,
    RedUnspecifiedTargetError,
    SecretExposureError,
    SilverTeam,
    TeamRegistry,
    WhiteTeam,
    YellowTeam,
)
from tests.test_phase1_coordinator import make_registry

def make_red(reg: TeamRegistry | None = None) -> RedTeam:
    return RedTeam(registry=reg or make_registry())


def make_purple(reg: TeamRegistry | None = None) -> PurpleTeam:
    return PurpleTeam(registry=reg or make_registry())


def ledger_backed_purple(reg: TeamRegistry, governance: WhiteTeam, task_id: str) -> tuple[PurpleTeam, str]:
    yellow = YellowTeam(registry=reg)
    result = yellow.run_check(
        task_id=task_id, actor="yellow.ver-1", check_type="security",
        command="retest", version="1", exit_status=0,
        artifacts_ref="artifact://retest", evidence_location="report://retest",
    )
    record = governance.record_yellow_output(task_id, (result,))[0]
    purple = PurpleTeam(registry=reg)
    purple.governance = governance
    return purple, record.evidence_id


# ---------------------------------------------------------------------------
# Red Team: findings
# ---------------------------------------------------------------------------

def test_report_finding_valid() -> None:
    finding = make_red().report_finding(
        task_id="task-1", actor="red.tar-1",
        title="deploy agent leaks token",
        reproduction=("1. run deploy", "2. observe trace"),
        impact="token visible in trace",
        severity="high",
        remediation_recommendation="rotate and scope tokens",
        targets=("deploy-agent:1.4",),
    )
    assert isinstance(finding, Finding)
    assert finding.severity == "high"
    assert finding.destructive is False


@pytest.mark.parametrize("secret", [
    "ghp_" + "A" * 25,
    "sk-live-" + "b" * 24,
    "password=SuperSecret123!",
    "hmac_secret=ephemeral123",
    "secret_value=ephemeral123",
    "hmacSecret=ephemeral123",
])
def test_finding_rejects_secret_material_at_construction(secret: str) -> None:
    # Exercise direct construction as well as the RedTeam factory path: no
    # unsafe Finding object should escape into caller memory.
    with pytest.raises(SecretExposureError):
        Finding(
            finding_id="find-test-secret",
            task_id="task-1",
            actor="red.tar-1",
            title="safe title",
            reproduction=(
                ("repro contains " + secret,)
                if "=" not in secret
                else ("repro contains secret-shaped credential",)
            ),
            impact="secret exposure",
            severity="high",
            remediation_recommendation=(
                secret if "=" in secret else "remove the credential"
            ),
            targets=("test-target",),
            techniques=(),
            destructive=False,
            approval_refs=(),
            timestamp="2026-09-25T00:00:00Z",
        )

    with pytest.raises(SecretExposureError):
        make_red().report_finding(
            task_id="task-1", actor="red.tar-1",
            title=("finding includes " + secret if "=" not in secret else "safe title"),
            reproduction=(("1. output " + secret,)
                          if "=" in secret else ("1. inspect output",)),
            impact="credential could be exposed",
            severity="high",
            remediation_recommendation="rotate credential",
            targets=("test-target",),
        )


def test_red_refuses_unspecified_targets() -> None:
    with pytest.raises(RedUnspecifiedTargetError):
        make_red().report_finding(
            task_id="task-1", actor="red.tar-1",
            title="generic", reproduction=("1. try things",),
            impact="unknown", severity="low",
            remediation_recommendation="none", targets=(),
        )


def test_red_refuses_destructive_without_approval() -> None:
    with pytest.raises(RedDestructiveTestRefusedError):
        make_red().report_finding(
            task_id="task-1", actor="red.tar-1",
            title="drop table", reproduction=("1. attempt",),
            impact="data loss", severity="critical",
            remediation_recommendation="backups",
            targets=("db:staging",), destructive=True,
        )


def test_red_allows_destructive_with_approval_refs() -> None:
    finding = make_red().report_finding(
        task_id="task-1", actor="red.tar-1",
        title="drop table", reproduction=("1. attempt",),
        impact="data loss", severity="critical",
        remediation_recommendation="backups",
        targets=("db:staging",), destructive=True,
        approval_refs=("evt-approval-1",),
    )
    assert finding.destructive is True
    assert finding.approval_refs == ("evt-approval-1",)


def test_finding_requires_complete_fields() -> None:
    red = make_red()
    with pytest.raises(InvalidFindingError):
        red.report_finding(task_id="task-1", actor="red.tar-1",
                           title="x", reproduction=(), impact="i",
                           severity="high", remediation_recommendation="r",
                           targets=("t",))
    with pytest.raises(InvalidFindingError):
        red.report_finding(task_id="task-1", actor="red.tar-1",
                           title="x", reproduction=("1. step",),
                           impact="", severity="high",
                           remediation_recommendation="r", targets=("t",))
    with pytest.raises(InvalidFindingError):
        red.report_finding(task_id="task-1", actor="red.tar-1",
                           title="x", reproduction=("1. step",),
                           impact="i", severity="catastrophic",
                           remediation_recommendation="r", targets=("t",))


def test_red_requires_red_actor() -> None:
    red = make_red()
    with pytest.raises(RedUnauthorizedActorError):
        red.report_finding(task_id="task-1", actor="blue.obs-1",
                           title="x", reproduction=("1. step",), impact="i",
                           severity="low", remediation_recommendation="r",
                           targets=("t",))
    with pytest.raises(RedUnauthorizedActorError):
        red.report_finding(task_id="task-1", actor="ghost.1",
                           title="x", reproduction=("1. step",), impact="i",
                           severity="low", remediation_recommendation="r",
                           targets=("t",))


def test_red_caps_are_readonly() -> None:
    from colorharness.registry import TEAM_CHARTER
    assert not (TEAM_CHARTER["red"] & {"branch_write", "config_write", "release"})


# ---------------------------------------------------------------------------
# Purple Team: closure validation
# ---------------------------------------------------------------------------

def test_validate_closure_valid() -> None:
    reg = make_registry()
    governance = WhiteTeam(registry=reg)
    purple, ref = ledger_backed_purple(reg, governance, "task-1")
    closure = purple.validate_closure(
        task_id="task-1", actor="purple.clo-1",
        finding_ref="find-1",
        controls=("token scoped to service",),
        re_test_refs=(ref,),
        verdict="closed",
    )
    assert isinstance(closure, Closure)
    assert closure.verdict == "closed"
    assert closure.re_test_refs == (ref,)


def test_purple_refuses_closure_without_re_test() -> None:
    with pytest.raises(PurpleNoReTestError):
        make_purple().validate_closure(
            task_id="task-1", actor="purple.clo-1",
            finding_ref="find-1", controls=("c",),
            re_test_refs=(), verdict="closed",
        )


def test_closure_requires_finding_and_controls() -> None:
    reg = make_registry()
    governance = WhiteTeam(registry=reg)
    purple, ref = ledger_backed_purple(reg, governance, "task-1")
    with pytest.raises(InvalidClosureError):
        purple.validate_closure(task_id="task-1", actor="purple.clo-1",
                                finding_ref="", controls=("c",),
                                re_test_refs=(ref,), verdict="closed")
    with pytest.raises(InvalidClosureError):
        purple.validate_closure(task_id="task-1", actor="purple.clo-1",
                                finding_ref="find-1", controls=(),
                                re_test_refs=(ref,), verdict="closed")
    with pytest.raises(InvalidClosureError):
        purple.validate_closure(task_id="task-1", actor="purple.clo-1",
                                finding_ref="find-1", controls=("c",),
                                re_test_refs=(ref,), verdict="maybe")


def test_closure_requires_purple_actor() -> None:
    with pytest.raises(PurpleUnauthorizedActorError):
        make_purple().validate_closure(
            task_id="task-1", actor="silver.build-1",
            finding_ref="find-1", controls=("c",),
            re_test_refs=("r",), verdict="closed",
        )


# ---------------------------------------------------------------------------
# White records red/purple output as evidence
# ---------------------------------------------------------------------------

def test_white_records_finding_and_closure(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    red = make_red(reg)
    finding = red.report_finding(
        task_id="task-1", actor="red.tar-1",
        title="token leak", reproduction=("1. run", "2. observe"),
        impact="exposure", severity="high",
        remediation_recommendation="rotate + scope",
        targets=("deploy-agent:1.4",),
    )
    purple = make_purple(reg)
    purple.governance = gov
    re_test = YellowTeam(registry=reg).run_check(
        task_id="task-1", actor="yellow.ver-1", check_type="security",
        command="retest", version="1", exit_status=0,
        artifacts_ref="artifact://retest", evidence_location="report://retest",
    )
    re_test_record = gov.record_yellow_output("task-1", (re_test,))[0]
    closure = purple.validate_closure(
        task_id="task-1", actor="purple.clo-1",
        finding_ref=finding.finding_id,
        controls=("token scoped",),
        re_test_refs=(re_test_record.evidence_id,),
        verdict="closed",
    )

    finding_records = gov.record_red_output("task-1", (finding,))
    closure_records = gov.record_purple_output("task-1", (closure,))

    assert finding_records[0].record_type == "finding"
    assert finding_records[0].payload["severity"] == "high"
    assert finding_records[0].payload["targets"] == ["deploy-agent:1.4"]

    assert closure_records[0].record_type == "remediation"
    assert closure_records[0].payload["verdict"] == "closed"
    assert closure_records[0].payload["re_test_ref"] == re_test_record.evidence_id
    assert closure_records[0].payload["change_ref"] == finding.finding_id
    assert gov.ledger.verify_chain()
    assert not gov.ledger.verify_manifest()


def test_white_refuses_unsupported_red_purple(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    with pytest.raises(Exception):
        gov.record_red_output("task-1", ("not-a-finding",))
    with pytest.raises(Exception):
        gov.record_purple_output("task-1", ("not-a-closure",))


# ---------------------------------------------------------------------------
# Full chain: red finding -> purple closure with re-test evidence
# ---------------------------------------------------------------------------

def test_finding_to_closure_chain(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    red = make_red(reg)
    purple = make_purple(reg)
    purple.governance = gov

    finding = red.report_finding(
        task_id="task-1", actor="red.tar-1",
        title="dependency vuln", reproduction=("1. npm audit", "2. observe CVE"),
        impact="remote code execution", severity="critical",
        remediation_recommendation="pin the dependency",
        targets=("app:prod-svc",), techniques=("dependency-scan",),
    )
    gov.record_red_output("task-1", (finding,))

    plan = gov.record_approval("task-1", gated_action="plan_approval",
                               approver="white.sys-1", scope={"repo": "demo"},
                               author="silver.build-1", approver_role="ci-operator")
    change = SilverTeam(registry=reg, governance=gov).present_change(
        task_id="task-1", actor="silver.build-1",
        change_type="config", branch="isolated/pin-dep",
        files=("package-lock.json",), diff_summary="pin dependency",
        plan_refs=(plan.evidence_id,),
        rollback_metadata={"steps": ["git revert pin-dep"]},
        configurations=("package-lock.json",),
    )
    gov.record_silver_output("task-1", (change,))

    re_test = YellowTeam(registry=reg).run_check(
        task_id="task-1", actor="yellow.ver-1",
        check_type="security", command="npm audit", version="npm 10",
        exit_status=0, artifacts_ref=change.manifest_id,
        evidence_location="audit://report",
    )
    gov.record_yellow_output("task-1", (re_test,))

    closure = purple.validate_closure(
        task_id="task-1", actor="purple.clo-1",
        finding_ref=finding.finding_id,
        controls=(change.manifest_id,),
        re_test_refs=(gov.ledger.records[-1].evidence_id,),
        verdict="closed",
        notes="dependency pinned and re-scanned clean",
    )
    gov.record_purple_output("task-1", (closure,))

    kinds = {r.record_type for r in gov.ledger.records}
    assert {"finding", "change", "test_result", "remediation"} <= kinds
    closure_record = [r for r in gov.ledger.records if r.record_type == "remediation"][0]
    assert closure_record.payload["re_test_ref"] == closure.re_test_refs[0]
    assert not closure_record.payload.get("secret")
    assert gov.ledger.verify_chain()
    assert not gov.ledger.verify_manifest()
