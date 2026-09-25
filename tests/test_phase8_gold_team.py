"""Phase 8 acceptance checks: Gold Team — versioned standards, reference
pipelines, and policy exceptions that require documented approval and expiry."""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from colorharness import (
    ExceptionGrant,
    ExceptionRequiresApproval,
    GoldTeam,
    GoldUnauthorizedActorError,
    InvalidExceptionError,
    InvalidStandardError,
    ReferencePipeline,
    Standard,
    TeamRegistry,
    UnboundedExceptionRefusedError,
    VersionConflictError,
    WhiteTeam,
)
from colorharness.secrets import SecretExposureError
from tests.test_phase1_coordinator import make_registry

FUTURE = int(time.time()) + 3600


def make_gold(reg: TeamRegistry | None = None, governance=None) -> GoldTeam:
    return GoldTeam(registry=reg or make_registry(), governance=governance)


def make_exception_context(tmp_path):
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl"))
    approval = gov.record_approval(
        "task-1", gated_action="policy_exception", approver="black.diag-1",
        approver_role="security-lead", scope={"repo": "demo"}, author="gold.plan-1",
    )
    return reg, gov, approval, make_gold(reg, gov)


# ---------------------------------------------------------------------------
# Standards
# ---------------------------------------------------------------------------

def test_author_standard_valid() -> None:
    gold = make_gold()
    standard = gold.author_standard(
        actor="gold.plan-1", standard_id="std-secrets", title="secrets policy",
        version="1.0", domain="secrets_policy",
        policies=("no secrets in manifests", "rotate quarterly"),
        rationale="keep credentials out of source",
    )
    assert isinstance(standard, Standard)
    assert standard.domain == "secrets_policy"
    assert standard.supersedes is None


def test_standard_version_is_dotted() -> None:
    with pytest.raises(InvalidStandardError):
        make_gold().author_standard(
            actor="gold.plan-1", standard_id="std-x", title="x",
            version="1", domain="secrets_policy",
            policies=("a",), rationale="r",
        )


def test_standard_version_must_increase() -> None:
    gold = make_gold()
    gold.author_standard(actor="gold.plan-1", standard_id="std-x", title="x",
                         version="1.0", domain="secrets_policy",
                         policies=("a",), rationale="r")
    with pytest.raises(VersionConflictError):
        gold.author_standard(actor="gold.plan-1", standard_id="std-x", title="x",
                             version="1.0", domain="secrets_policy",
                             policies=("b",), rationale="r2")
    with pytest.raises(VersionConflictError):
        gold.author_standard(actor="gold.plan-1", standard_id="std-x", title="x",
                             version="0.9", domain="secrets_policy",
                             policies=("b",), rationale="r2")
    v2 = gold.author_standard(actor="gold.plan-1", standard_id="std-x", title="x",
                              version="2.0", domain="secrets_policy",
                              policies=("b",), rationale="r2",
                              supersedes="std-x@1.0")
    assert v2.supersedes == "std-x@1.0"


def test_standard_needs_policies_and_rationale() -> None:
    gold = make_gold()
    with pytest.raises(InvalidStandardError):
        gold.author_standard(actor="gold.plan-1", standard_id="std-x",
                             title="x", version="1.0", domain="secrets_policy",
                             policies=(), rationale="r")
    with pytest.raises(InvalidStandardError):
        gold.author_standard(actor="gold.plan-1", standard_id="std-x",
                             title="x", version="1.0", domain="secrets_policy",
                             policies=("a",), rationale="")


def test_policy_as_code_rejects_secrets() -> None:
    with pytest.raises(SecretExposureError):
        make_gold().author_standard(
            actor="gold.plan-1", standard_id="std-bad", title="bad",
            version="1.0", domain="secrets_policy",
            policies=("allow ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAA",),
            rationale="r",
        )


def test_gold_requires_gold_actor() -> None:
    gold = make_gold()
    with pytest.raises(GoldUnauthorizedActorError):
        gold.author_standard(actor="silver.build-1", standard_id="std-x",
                             title="x", version="1.0", domain="secrets_policy",
                             policies=("a",), rationale="r")
    with pytest.raises(GoldUnauthorizedActorError):
        gold.author_standard(actor="ghost.1", standard_id="std-x",
                             title="x", version="1.0", domain="secrets_policy",
                             policies=("a",), rationale="r")


# ---------------------------------------------------------------------------
# Reference pipelines
# ---------------------------------------------------------------------------

def test_define_pipeline_valid() -> None:
    pipeline = make_gold().define_pipeline(
        actor="gold.plan-1", pipeline_id="pipe-cd", title="golden cd",
        version="1.0", stages=("build", "test", "promote"),
        triggers=("push to main", "manual approval"),
    )
    assert isinstance(pipeline, ReferencePipeline)
    assert pipeline.stages == ("build", "test", "promote")


def test_pipeline_version_and_content_rules() -> None:
    gold = make_gold()
    with pytest.raises(InvalidStandardError):
        gold.define_pipeline(actor="gold.plan-1", pipeline_id="pipe-cd",
                             title="x", version="v1", stages=("build",), triggers=("push",))
    with pytest.raises(InvalidStandardError):
        gold.define_pipeline(actor="gold.plan-1", pipeline_id="pipe-cd",
                             title="x", version="1.0", stages=(), triggers=("push",))
    gold.define_pipeline(actor="gold.plan-1", pipeline_id="pipe-cd",
                         title="x", version="1.0", stages=("build",), triggers=("push",))
    with pytest.raises(VersionConflictError):
        gold.define_pipeline(actor="gold.plan-1", pipeline_id="pipe-cd",
                             title="x", version="1.0", stages=("build",), triggers=("push",))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

def test_exception_requires_approval() -> None:
    with pytest.raises(ExceptionRequiresApproval):
        make_gold().grant_exception(
            task_id="task-1", actor="gold.plan-1", standard_ref="std-x@1.0",
            approver="platform-owner", approval_ref="", scope="db:staging",
            expiry_epoch=FUTURE, reason="quarantine needs a window",
        )


def test_exception_refuses_unbounded_expiry(tmp_path) -> None:
    _, _, approval, gold = make_exception_context(tmp_path)
    with pytest.raises(UnboundedExceptionRefusedError):
        gold.grant_exception(
            task_id="task-1", actor="gold.plan-1", standard_ref="std-x@1.0",
            approver="security-lead", approval_ref=approval.approval_id,
            scope="db:staging", expiry_epoch=int(time.time()) - 1,
            reason="expired approval never counts",
        )
    with pytest.raises(UnboundedExceptionRefusedError):
        gold.grant_exception(
            task_id="task-1", actor="gold.plan-1", standard_ref="std-x@1.0",
            approver="security-lead", approval_ref=approval.approval_id,
            scope="db:staging", expiry_epoch=0, reason="zero means no expiry",
        )


def test_exception_valid(tmp_path) -> None:
    _, _, approval, gold = make_exception_context(tmp_path)
    exc = gold.grant_exception(
        task_id="task-1", actor="gold.plan-1", standard_ref="std-x@1.0",
        approver="security-lead", approval_ref=approval.approval_id,
        scope="db:staging", expiry_epoch=FUTURE,
        reason="staging quarantine within the incident window",
    )
    assert isinstance(exc, ExceptionGrant)
    assert exc.scope == "db:staging"
    assert exc.approval_ref == approval.approval_id


def test_gold_rejects_forged_or_self_approved_exception(tmp_path) -> None:
    _, gov, approval, gold = make_exception_context(tmp_path)
    with pytest.raises(ExceptionRequiresApproval):
        gold.grant_exception(
            task_id="task-1", actor="gold.plan-1", standard_ref="std-x@1.0",
            approver="security-lead", approval_ref="apr-FAKE", scope="staging",
            expiry_epoch=FUTURE, reason="forged ref",
        )

    # Exercise the mint-time guard even if a compromised upstream registry
    # supplied an otherwise-live approval attributed to the exception author.
    gov._approvals[approval.approval_id] = replace(approval, approver="gold.plan-1")
    with pytest.raises(InvalidExceptionError, match="cannot approve their own"):
        gold.grant_exception(
            task_id="task-1", actor="gold.plan-1", standard_ref="std-x@1.0",
            approver="security-lead", approval_ref=approval.approval_id,
            scope="staging", expiry_epoch=FUTURE, reason="self approval",
        )


def test_exception_requires_scope_and_reason(tmp_path) -> None:
    _, _, approval, gold = make_exception_context(tmp_path)
    with pytest.raises(InvalidExceptionError):
        gold.grant_exception(task_id="task-1", actor="gold.plan-1",
                             standard_ref="std-x@1.0", approver="a",
                             approval_ref=approval.approval_id, scope="", expiry_epoch=FUTURE,
                             reason="r")
    with pytest.raises(InvalidExceptionError):
        gold.grant_exception(task_id="task-1", actor="gold.plan-1",
                             standard_ref="std-x@1.0", approver="a",
                             approval_ref=approval.approval_id, scope="db", expiry_epoch=FUTURE,
                             reason="")


def test_gold_caps_are_policy_write() -> None:
    from colorharness.registry import TEAM_CHARTER
    assert TEAM_CHARTER["gold"] == frozenset({"policy_write"})
    assert not (TEAM_CHARTER["gold"] & {"release_plan", "branch_write"})


# ---------------------------------------------------------------------------
# White records gold output as evidence
# ---------------------------------------------------------------------------

def test_white_records_gold_output(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    gold = make_gold(reg, gov)
    standard = gold.author_standard(
        actor="gold.plan-1", standard_id="std-secrets", title="secrets policy",
        version="1.0", domain="secrets_policy",
        policies=("no secrets in manifests",), rationale="keep credentials out",
    )
    pipeline = gold.define_pipeline(
        actor="gold.plan-1", pipeline_id="pipe-cd", title="golden cd",
        version="1.0", stages=("build", "promote"), triggers=("push",),
    )
    approval = gov.record_approval(
        "task-1", gated_action="policy_exception", approver="black.diag-1",
        approver_role="security-lead", scope={"repo": "demo"}, author="gold.plan-1",
    )
    exc = gold.grant_exception(
        task_id="task-1", actor="gold.plan-1", standard_ref="std-secrets@1.0",
        approver="security-lead", approval_ref=approval.approval_id,
        scope="staging", expiry_epoch=FUTURE, reason="monitoring window",
    )

    records = gov.record_gold_output("task-1", (standard, pipeline, exc))

    kinds = [r.record_type for r in records]
    assert kinds == ["standard", "pipeline", "exception"]
    assert records[0].payload["version"] == "1.0"
    assert records[1].payload["stages"] == ["build", "promote"]
    assert records[2].payload["expiry_epoch"] == FUTURE
    assert records[2].payload["approval_ref"] == approval.approval_id
    assert gov.ledger.verify_chain()
    assert not gov.ledger.verify_manifest()


def test_white_refuses_non_gold_items(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    with pytest.raises(TypeError):
        gov.record_gold_output("task-1", ("not-a-standard",))


# ---------------------------------------------------------------------------
# Integration: gold standard -> exception + purple remediation chain
# ---------------------------------------------------------------------------

def test_gold_supports_finding_remediation_chain(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    gold = make_gold(reg)

    from colorharness import PurpleTeam, RedTeam, SilverTeam, YellowTeam

    standard = gold.author_standard(
        actor="gold.plan-1", standard_id="std-secrets", title="secrets policy",
        version="1.0", domain="secrets_policy",
        policies=("no secrets in traces",), rationale="contain exposure",
    )
    gov.record_gold_output("task-1", (standard,))

    finding = RedTeam(registry=reg).report_finding(
        task_id="task-1", actor="red.tar-1",
        title="trace leaks token", reproduction=("run deploy", "observe trace"),
        impact="credential exposure", severity="high",
        remediation_recommendation="stop logging tokens",
        targets=("deploy-agent:1.4",),
    )
    gov.record_red_output("task-1", (finding,))

    plan = gov.record_approval("task-1", gated_action="plan_approval",
                               approver="white.sys-1", scope={"repo": "demo"},
                               author="silver.build-1", approver_role="ci-operator")
    change = SilverTeam(registry=reg, governance=gov).present_change(
        task_id="task-1", actor="silver.build-1",
        change_type="branch", branch="isolated/no-tokens",
        files=("tracing.cfg",), diff_summary="redact tokens",
        plan_refs=(plan.evidence_id,),
        rollback_metadata={"steps": ["git revert no-tokens"]},
    )
    gov.record_silver_output("task-1", (change,))

    re_test = YellowTeam(registry=reg).run_check(
        task_id="task-1", actor="yellow.ver-1", check_type="security",
        command="trace-scan", version="scan 1.0", exit_status=0,
        artifacts_ref=change.manifest_id, evidence_location="scan://report",
    )
    gov.record_yellow_output("task-1", (re_test,))

    purple = PurpleTeam(registry=reg)
    purple.governance = gov
    closure = purple.validate_closure(
        task_id="task-1", actor="purple.clo-1",
        finding_ref=finding.finding_id, controls=("redacted tracing",),
        re_test_refs=(gov.ledger.records[-1].evidence_id,), verdict="closed",
    )
    gov.record_purple_output("task-1", (closure,))

    kinds = {r.record_type for r in gov.ledger.records}
    assert {"standard", "finding", "change", "test_result", "remediation"} <= kinds
    standard_ref = [r for r in gov.ledger.records if r.record_type == "standard"][0]
    assert standard_ref.payload["domain"] == "secrets_policy"
    assert gov.ledger.verify_chain()
    assert not gov.ledger.verify_manifest()
