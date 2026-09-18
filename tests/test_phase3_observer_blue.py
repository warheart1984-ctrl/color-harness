"""Phase 3 acceptance checks: Observer (read-only facts) and Blue Team
(monitoring, alerts, recommendations, runbooks), plus the governed write paths
on White Team that turn facts and interpretations into ledger evidence."""

from __future__ import annotations

import pytest

from colorharness import (
    Alert,
    BlueTeam,
    Coordinator,
    EvidenceLedger,
    Observation,
    Observer,
    Recommendation,
    RunbookEntry,
    TeamRegistry,
    WhiteTeam,
)
from colorharness.blue import BlueTeamError, NoEvidenceError, UnauthorizedActorError
from colorharness._common import Trigger
from colorharness.observer import (
    InterpretationInObservationError,
    ObservationTypeError,
    ObserverError,
)
from colorharness.scope import validate_scope
from tests.test_phase1_coordinator import make_registry

DEV = {"ci_cd": {"environments": ["staging"]}, "repo": "color-harness"}


def make_observer() -> Observer:
    return Observer("observer.ro-1")


def make_blue(reg: TeamRegistry | None = None) -> BlueTeam:
    return BlueTeam(registry=reg or make_registry())


# ---------------------------------------------------------------------------
# Observer: read-only facts collection
# ---------------------------------------------------------------------------

def test_observer_collects_fact_without_writing(tmp_path) -> None:
    obs = make_observer().collect(
        task_id="task-1",
        observation_type="health",
        detail={"endpoint": "/healthz", "status_code": 200},
        source="probe://healthz",
    )
    assert isinstance(obs, Observation)
    assert obs.observation_id.startswith("obs-")
    assert obs.task_id == "task-1"
    assert obs.payload() == {
        "observation_type": "health",
        "detail": {"endpoint": "/healthz", "status_code": 200},
    }
    assert not list(tmp_path.iterdir()), "observer must never create files"


def test_observer_holds_no_ledger_or_storage() -> None:
    obs = Observer()
    assert not hasattr(obs, "ledger")
    assert not hasattr(obs, "path")
    assert not hasattr(obs, "store_path")


def test_observer_rejects_unknown_type() -> None:
    with pytest.raises(ObservationTypeError):
        make_observer().collect(
            task_id="t1", observation_type="dream", detail={"x": 1},
        )


def test_observer_rejects_empty_detail() -> None:
    with pytest.raises(ObserverError):
        make_observer().collect(task_id="t1", observation_type="metrics", detail={})


def test_observer_rejects_interpretation_keys() -> None:
    with pytest.raises(InterpretationInObservationError):
        make_observer().collect(
            task_id="t1", observation_type="logs",
            detail={"line": "x", "conclusion": "service is down"},
        )


def test_observer_accepts_all_fact_types() -> None:
    obs = make_observer()
    for kind in ("logs", "metrics", "health", "ci", "dependency", "repo_state", "changes"):
        result = obs.collect(task_id="t1", observation_type=kind, detail={"k": "v"})
        assert result.observation_type == kind


# ---------------------------------------------------------------------------
# White records observations as evidence (observer never writes)
# ---------------------------------------------------------------------------

def test_white_records_observations_as_evidence(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    obs = Observer()
    one = obs.collect(task_id="task-1", observation_type="health",
                      detail={"status_code": 200}, source="probe://h")
    two = obs.collect(task_id="task-1", observation_type="metrics",
                      detail={"metric": "error_rate", "value": 0.04},
                      source="metrics://app")

    validate_scope(DEV)
    records = gov.record_observations("task-1", (one, two))
    assert len(records) == 2
    for record, source_obs in zip(records, (one, two)):
        assert record.record_type == "observation"
        assert record.task_id == "task-1"
        assert record.payload == source_obs.payload()
        assert source_obs.observation_id in record.refs
    assert gov.ledger.verify_chain()


def test_white_refuses_interpretation_at_write(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    obs = make_observer().collect(
        task_id="task-1", observation_type="logs",
        detail={"line": "slow query"}, source="logs://db",
    )
    object.__setattr__(obs, "detail", {**obs.detail, "assessment": "db is slow"})
    with pytest.raises(Exception) as exc:
        gov.record_observations("task-1", (obs,))
    assert "interpretation" in str(exc.value)
    assert len(gov.ledger) == 0, "a refused observation writes nothing"


# ---------------------------------------------------------------------------
# Blue Team: recommendations, monitoring alerts, runbooks
# ---------------------------------------------------------------------------

def test_blue_recommend_requires_blue_actor() -> None:
    blue = make_blue()
    with pytest.raises(UnauthorizedActorError):
        blue.recommend(
            "task-1", actor=Coordinator.SYSTEM_AGENT, recommended_action="roll back",
            rationale="r", evidence_refs=("evt-1",),
        )
    with pytest.raises(UnauthorizedActorError):
        blue.recommend(
            task_id="task-1", actor="ghost.1", recommended_action="x",
            rationale="r", evidence_refs=("evt-1",),
        )


def test_blue_recommend_requires_evidence() -> None:
    blue = make_blue()
    with pytest.raises(NoEvidenceError):
        blue.recommend(
            task_id="task-1", actor="blue.obs-1", recommended_action="roll back",
            rationale="r", evidence_refs=(),
        )


def test_blue_recommend_cites_evidence() -> None:
    blue = make_blue()
    rec = blue.recommend(
        task_id="task-1", actor="blue.obs-1", recommended_action="halt rollout",
        rationale="error rate above threshold", evidence_refs=("evt-obs-1",),
        severity="critical",
    )
    assert isinstance(rec, Recommendation)
    assert rec.evidence_refs == ("evt-obs-1",)
    assert rec.severity == "critical"


def test_blue_monitor_fires_warning_and_critical() -> None:
    obs = Observer()
    warn = obs.collect(task_id="task-1", observation_type="metrics",
                       detail={"metric": "error_rate", "value": 0.06},
                       source="metrics://app")
    critical = obs.collect(task_id="task-1", observation_type="metrics",
                           detail={"metric": "latency_p99", "value": 1200.0},
                           source="metrics://app")
    healthy = obs.collect(task_id="task-1", observation_type="metrics",
                          detail={"metric": "cpu", "value": 10.0},
                          source="metrics://app")
    alerts = make_blue().monitor(
        task_id="task-1",
        observations=(warn, critical, healthy),
        thresholds={"error_rate": (0.05, 0.10), "latency_p99": (500.0, 1000.0)},
    )
    by_metric = {a.metric: a for a in alerts}
    assert by_metric["error_rate"].severity == "warning"
    assert by_metric["latency_p99"].severity == "critical"
    assert "cpu" not in by_metric
    refs = set()
    for alert in alerts:
        assert isinstance(alert, Alert)
        assert alert.observation_refs
        refs.update(alert.observation_refs)
    assert warn.observation_id in refs and critical.observation_id in refs


def test_blue_eligibility_rejects_interpretive_observations() -> None:
    blue = make_blue()
    clean = make_observer().collect(task_id="task-1", observation_type="health",
                                    detail={"status": "up"})
    dirty = make_observer().collect(task_id="task-1", observation_type="health",
                                    detail={"status": "up"})
    object.__setattr__(dirty, "detail", {**dirty.detail, "conclusion": "fine"})
    assert blue.eligibility("task-1", (clean,))
    assert not blue.eligibility("task-1", (dirty,))


def test_blue_draft_runbook_requires_actor_and_source() -> None:
    blue = make_blue()
    with pytest.raises(NoEvidenceError):
        blue.draft_runbook(task_id="task-1", actor="blue.obs-1", procedure="p",
                           source_refs=())
    with pytest.raises(UnauthorizedActorError):
        blue.draft_runbook(task_id="task-1", actor="yellow.ver-1", procedure="p",
                           source_refs=("evt-1",))
    entry = blue.draft_runbook(task_id="task-1", actor="blue.obs-1",
                               procedure="1. confirm 2. roll back",
                               source_refs=("evt-1",), severity="critical")
    assert isinstance(entry, RunbookEntry)
    assert entry.source_refs == ("evt-1",)


# ---------------------------------------------------------------------------
# White records blue output as evidence
# ---------------------------------------------------------------------------

def test_white_records_blue_output(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    blue = make_blue()
    alert = blue.monitor(
        task_id="task-1",
        observations=(make_observer().collect(
            task_id="task-1", observation_type="metrics",
            detail={"metric": "error_rate", "value": 0.12}, source="metrics://app",
        ),),
        thresholds={"error_rate": (0.05, 0.10)},
    )[0]
    rec = blue.recommend(task_id="task-1", actor="blue.obs-1",
                         recommended_action="halt rollout", rationale="critical",
                         evidence_refs=(alert.alert_id,))
    run = blue.draft_runbook(task_id="task-1", actor="blue.obs-1",
                             procedure="1. halt 2. rollback",
                             source_refs=(alert.alert_id,))

    records = gov.record_blue_output("task-1", (alert, rec, run))
    kinds = sorted(r.record_type for r in records)
    assert kinds == ["alert", "recommendation", "runbook_entry"]
    alert_record = [r for r in records if r.record_type == "alert"][0]
    assert alert_record.payload["metric"] == "error_rate"
    assert alert_record.payload["observed_value"] == 0.12
    assert alert_record.payload["severity"] == "critical"
    assert gov.ledger.verify_chain()


def test_blue_observation_to_alert_evidence_chain(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    before = gov.ledger.manifest_digest()

    obs = make_observer().collect(
        task_id="task-1", observation_type="metrics",
        detail={"metric": "error_rate", "value": 0.21}, source="metrics://app",
    )
    gov.record_observations("task-1", (obs,))
    alert = make_blue().monitor(
        task_id="task-1", observations=(obs,),
        thresholds={"error_rate": (0.05, 0.10)},
    )[0]
    gov.record_blue_output("task-1", (alert,))

    kinds = {r.record_type for r in gov.ledger.records}
    assert kinds == {"observation", "alert"}
    assert gov.ledger.verify_chain()
    assert gov.ledger.verify_manifest(gov.ledger.manifest_digest())
    assert gov.ledger.manifest_digest() != before


def test_blue_output_requires_supported_objects(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    with pytest.raises(Exception):
        gov.record_blue_output("task-1", ("not-an-alert",))


# ---------------------------------------------------------------------------
# Full decorator integration smoke (coordinator + registry + observer + blue)
# ---------------------------------------------------------------------------

def test_phase3_end_to_end(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "events.jsonl"), governance=gov)

    task = c.create_task(title="deploy pipeline", scope=DEV, risk="green")
    c.apply_transition(
        task["task_id"],
        Trigger.ROUTE,
        actor=Coordinator.SYSTEM_AGENT,
        reason="route to observe",
        evidence_refs=("task://tx",),
        request_id="ph3-route",
    )

    obs = make_observer().collect(
        task_id=task["task_id"], observation_type="ci",
        detail={"pipeline": "build", "exit_status": 1},
        source="ci://build",
    )
    obs_records = gov.record_observations(task["task_id"], (obs,))

    alerts = make_blue().monitor(
        task_id=task["task_id"], observations=(obs,),
        thresholds={"error_rate": (0.05, 0.10)},
    )
    assert alerts == []

    gov.record_blue_output(task["task_id"], alerts)
    assert gov.ledger.verify_chain()
    assert obs_records[0].payload["detail"]["exit_status"] == 1