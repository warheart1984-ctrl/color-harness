"""Phase 4 acceptance checks: Black Team diagnostics — hypotheses, controlled
experiments, and evidence-based diagnoses, plus the coordinator's evidence
gates (OBSERVATIONS_READY / DIAGNOSIS_ACCEPTED require recorded evidence)."""

from __future__ import annotations

import pytest

from colorharness import (
    BlackNoEvidenceError,
    BlackNoUncertaintyError,
    BlackTeam,
    BlackTeamError,
    BlackUnauthorizedActorError,
    Coordinator,
    Diagnosis,
    Experiment,
    Hypothesis,
    InvalidInputError,
    Observer,
    TeamRegistry,
    WhiteTeam,
)
from colorharness._common import RejectionCode, TaskState, Trigger
from colorharness.scope import validate_scope
from tests.test_phase1_coordinator import make_registry

DEV = {"ci_cd": {"environments": ["staging"]}, "repo": "color-harness"}


def make_black(reg: TeamRegistry | None = None) -> BlackTeam:
    return BlackTeam(registry=reg or make_registry())


# ---------------------------------------------------------------------------
# Black Team unit behavior
# ---------------------------------------------------------------------------

def test_hypothesize_valid() -> None:
    hyp = make_black().hypothesize(
        task_id="task-1", actor="black.diag-1",
        hypothesis="deploy agent timed out mid-step",
        confidence="medium",
        alternatives=("config race", "rate limit"),
        discriminator="re-run with verbose step timing",
        evidence_refs=("evt-obs-1",),
    )
    assert isinstance(hyp, Hypothesis)
    assert hyp.confidence == "medium"
    assert hyp.evidence_refs == ("evt-obs-1",)


def test_hypothesize_requires_evidence() -> None:
    with pytest.raises(BlackNoEvidenceError):
        make_black().hypothesize(
            task_id="task-1", actor="black.diag-1",
            hypothesis="x", alternatives=("a",), discriminator="d",
            evidence_refs=(),
        )


def test_hypothesize_requires_alternatives() -> None:
    with pytest.raises(BlackNoUncertaintyError):
        make_black().hypothesize(
            task_id="task-1", actor="black.diag-1",
            hypothesis="x", alternatives=(),
            discriminator="d", evidence_refs=("evt-1",),
        )


def test_hypothesize_rejects_unknown_confidence() -> None:
    with pytest.raises(InvalidInputError):
        make_black().hypothesize(
            task_id="task-1", actor="black.diag-1",
            hypothesis="x", confidence="certain",
            alternatives=("a",), discriminator="d", evidence_refs=("evt-1",),
        )


def test_diagnose_valid() -> None:
    diag = make_black().diagnose(
        task_id="task-1", actor="black.diag-1",
        diagnosis="timeout caused by expired token rotation",
        confidence="high",
        evidence_refs=("evt-obs-1", "evt-exp-1"),
        alternatives=("network partition",),
    )
    assert isinstance(diag, Diagnosis)
    assert diag.confidence == "high"
    assert diag.alternatives == ("network partition",)


def test_diagnose_requires_uncertainty() -> None:
    with pytest.raises(BlackNoUncertaintyError):
        make_black().diagnose(
            task_id="task-1", actor="black.diag-1",
            diagnosis="it is broken", confidence="low",
            evidence_refs=("evt-obs-1",), alternatives=(),
        )


def test_diagnose_requires_evidence() -> None:
    with pytest.raises(BlackNoEvidenceError):
        make_black().diagnose(
            task_id="task-1", actor="black.diag-1",
            diagnosis="timeout", confidence="low",
            evidence_refs=(), alternatives=("a",),
        )


def test_black_requires_black_actor() -> None:
    black = make_black()
    with pytest.raises(BlackUnauthorizedActorError):
        black.diagnose(
            task_id="task-1", actor=Coordinator.SYSTEM_AGENT,
            diagnosis="d", confidence="low",
            evidence_refs=("evt-1",), alternatives=("a",),
        )
    with pytest.raises(BlackUnauthorizedActorError):
        black.diagnose(
            task_id="task-1", actor="yellow.ver-1",
            diagnosis="d", confidence="low",
            evidence_refs=("evt-1",), alternatives=("a",),
        )
    with pytest.raises(BlackUnauthorizedActorError):
        black.diagnose(
            task_id="task-1", actor="ghost.1",
            diagnosis="d", confidence="low",
            evidence_refs=("evt-1",), alternatives=("a",),
        )


def test_experiment_valid_and_gated() -> None:
    black = make_black()
    with pytest.raises(BlackTeamError):
        black.experiment(task_id="task-1", actor="black.diag-1",
                         setup={}, inputs_ref="x", result_ref="y")
    exp = black.experiment(task_id="task-1", actor="black.diag-1",
                           setup={"replay": "trace.json"}, inputs_ref="trace://1",
                           result_ref="result://1", verified=False)
    assert isinstance(exp, Experiment)
    assert exp.verified is False


# ---------------------------------------------------------------------------
# White records black output as evidence
# ---------------------------------------------------------------------------

def test_white_records_black_output(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    black = make_black()
    hyp = black.hypothesize(
        task_id="task-1", actor="black.diag-1",
        hypothesis="deploy timeout", confidence="medium",
        alternatives=("config race",), discriminator="verbose timing",
        evidence_refs=("evt-obs-1",),
    )
    exp = black.experiment(task_id="task-1", actor="black.diag-1",
                           setup={"replay": "trace.json"}, inputs_ref="trace://1",
                           result_ref="result://1", verified=True)
    diag = black.diagnose(
        task_id="task-1", actor="black.diag-1",
        diagnosis="token rotation expired", confidence="high",
        evidence_refs=(exp.experiment_id,), alternatives=("network partition",),
    )

    records = gov.record_black_output("task-1", (hyp, exp, diag))
    kinds = sorted(r.record_type for r in records)
    assert kinds == ["diagnosis", "experiment", "hypothesis"]
    hyp_record = [r for r in records if r.record_type == "hypothesis"][0]
    assert hyp_record.payload["confidence"] == "medium"
    assert hyp_record.payload["alternatives"] == ["config race"]
    diag_record = [r for r in records if r.record_type == "diagnosis"][0]
    assert diag_record.payload["evidence_refs"] == [exp.experiment_id]
    assert gov.ledger.verify_chain()


def test_white_rejects_unsupported_black_output(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    with pytest.raises(Exception):
        gov.record_black_output("task-1", ("not-black-output",))


def test_has_evidence_semantics(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    assert not gov.has_evidence("task-1", "observation")
    obs = Observer().collect(task_id="task-1", observation_type="health",
                             detail={"status": "up"})
    gov.record_observations("task-1", (obs,))
    assert gov.has_evidence("task-1", "observation")
    assert not gov.has_evidence("task-1", "diagnosis")


# ---------------------------------------------------------------------------
# Coordinator evidence gates
# ---------------------------------------------------------------------------

def test_coordinator_gates_progress_on_recorded_evidence(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="orange")
    c.apply_transition(task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("log://route",), request_id="r1")

    blocked = c.apply_transition(
        task["task_id"], Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
        reason="obs", evidence_refs=("log://obs",), request_id="r2",
    )
    assert blocked["success"] is False
    assert blocked["error"]["code"] == RejectionCode.EVIDENCE_NOT_RECORDED.value
    assert c.get_task(task["task_id"])["state"] == TaskState.OBSERVE.value

    obs = Observer().collect(task_id=task["task_id"], observation_type="metrics",
                             detail={"metric": "error_rate", "value": 0.2})
    gov.record_observations(task["task_id"], (obs,))
    ok = c.apply_transition(
        task["task_id"], Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
        reason="obs", evidence_refs=("log://obs",), request_id="r3",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.DIAGNOSE.value

    blocked = c.apply_transition(
        task["task_id"], Trigger.DIAGNOSIS_ACCEPTED, actor="black.diag-1",
        reason="diag", evidence_refs=("log://diag",), request_id="r4",
    )
    assert blocked["success"] is False
    assert blocked["error"]["code"] == RejectionCode.EVIDENCE_NOT_RECORDED.value

    diag = make_black(reg).diagnose(
        task_id=task["task_id"], actor="black.diag-1",
        diagnosis="token rotation expired", confidence="medium",
        evidence_refs=(obs.observation_id,), alternatives=("network partition",),
    )
    gov.record_black_output(task["task_id"], (diag,))
    ok = c.apply_transition(
        task["task_id"], Trigger.DIAGNOSIS_ACCEPTED, actor="black.diag-1",
        reason="diag", evidence_refs=("log://diag",), request_id="r5",
    )
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.PLAN.value


def test_evidence_gates_ignored_without_governance(tmp_path) -> None:
    c = Coordinator(registry=make_registry(), store_path=str(tmp_path / "e.jsonl"))
    task = c.create_task(title="t", scope={})
    c.apply_transition(task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="r", evidence_refs=("x",), request_id="r1")
    result = c.apply_transition(
        task["task_id"], Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
        reason="r", evidence_refs=("x",), request_id="r2",
    )
    assert result["success"] is True


# ---------------------------------------------------------------------------
# Full chain: observe -> hypothesize -> experiment -> diagnose -> accepted
# ---------------------------------------------------------------------------

def test_observe_to_diagnosis_chain(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=gov)
    task = c.create_task(title="incident", scope=DEV, risk="yellow")
    c.apply_transition(task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("log://route",), request_id="r1")

    obs = Observer().collect(task_id=task["task_id"], observation_type="ci",
                             detail={"pipeline": "deploy", "exit_status": 1},
                             source="ci://deploy")
    gov.record_observations(task["task_id"], (obs,))
    c.apply_transition(task["task_id"], Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
                       reason="obs", evidence_refs=("log://obs",), request_id="r2")

    black = make_black(reg)
    hyp = black.hypothesize(
        task_id=task["task_id"], actor="black.diag-1",
        hypothesis="token rotation expired", confidence="medium",
        alternatives=("permission drift",), discriminator="inspect token age",
        evidence_refs=(obs.observation_id,),
    )
    exp = black.experiment(task_id=task["task_id"], actor="black.diag-1",
                           setup={"inspect": "token_age"}, inputs_ref=obs.observation_id,
                           result_ref="verify://token", verified=True)
    diag = black.diagnose(
        task_id=task["task_id"], actor="black.diag-1",
        diagnosis="deploy agent token expired mid-rotation",
        confidence="high",
        evidence_refs=(obs.observation_id, exp.experiment_id),
        alternatives=("permission drift",),
    )
    gov.record_black_output(task["task_id"], (hyp, exp, diag))

    ok = c.apply_transition(task["task_id"], Trigger.DIAGNOSIS_ACCEPTED,
                            actor="black.diag-1", reason="diag accepted",
                            evidence_refs=("log://diag",), request_id="r3")
    assert ok["success"] is True
    assert c.get_task(task["task_id"])["state"] == TaskState.PLAN.value

    kinds = {r.record_type for r in gov.ledger.records}
    assert {"observation", "hypothesis", "experiment", "diagnosis"} <= kinds
    assert gov.ledger.verify_chain()
    assert gov.ledger.verify_manifest()

    validate_scope(DEV)