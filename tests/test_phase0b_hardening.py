"""Phase 0b hardening acceptance: DevOps scope allowlist, secret scanning,
reviewer roles + approval quorum/expiry, idempotency fingerprints, watchdog
quarantine/escalation, and ledger manifest digest."""

from __future__ import annotations

import time

import pytest

from colorharness import (
    Coordinator,
    EvidenceLedger,
    TeamRegistry,
    WhiteTeam,
    scope_covers,
)
from colorharness._common import RejectionCode, TaskState, Trigger
from colorharness.eventlog import (
    IDEMPOTENCY_CONFLICT,
    Event,
    EventLog,
    idempotency_fingerprint,
)
from colorharness.governance import (
    AmbiguousRoleError,
    GovernanceError,
    RoleRequiredError,
    RoleRiskForbidden,
)
from colorharness.ledger import canonical_json, sha256_hex
from colorharness.registry import RoleNotAllowedError, UnknownRoleError
from colorharness.scope import (
    DEVOPS_ALLOWLIST,
    ScopeOutOfBoundsError,
    out_of_bounds_keys,
    validate_scope,
)
from colorharness.secrets import (
    SecretExposureError,
    scan_for_secrets,
    raise_if_secret,
)
from colorharness.watchdog import (
    DEFAULT_STALE_BLOCK_SECONDS,
    HEARTBEAT_MISSES_THRESHOLD,
    SYSTEM_AGENT as WATCHDOG_AGENT,
    Watchdog,
)
from tests.test_phase1_coordinator import (
    FULL_PATH,
    _record_gate_evidence,
    make_registry,
)

DEV = {"ci_cd": {"environments": ["staging"]}, "repo": "color-harness"}
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmA="


# ---------------------------------------------------------------------------
# Scope allowlist
# ---------------------------------------------------------------------------

def test_allowlist_domains() -> None:
    assert "database" not in DEVOPS_ALLOWLIST
    assert "ci_cd" in DEVOPS_ALLOWLIST


def test_validate_scope_accepts_known_domains() -> None:
    validate_scope(DEV)


def test_scope_details_without_domain_rejected() -> None:
    try:
        validate_scope({"environments": ["prod"], "commands": ["rm -rf /"]})
    except ScopeOutOfBoundsError:
        pass
    else:
        raise AssertionError("detail keys cannot substitute for an allowed domain")


def test_out_of_bounds_domain_rejected() -> None:
    bad = out_of_bounds_keys({"ci_cd": {}, "database": {"engine": "postgres"}})
    assert bad == ["database"]
    try:
        validate_scope({"database": {}})
    except ScopeOutOfBoundsError:
        pass
    else:
        raise AssertionError("out-of-bounds scope must raise")


def test_coordinator_rejects_out_of_bounds_scope(tmp_path) -> None:
    reg = make_registry()
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=WhiteTeam(registry=reg))
    result = c.create_task(
        title="steal rows", scope={"database": {"engine": "postgres"}},
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.SCOPE_OUT_OF_BOUNDS.value
    assert c.event_count() == 0


def test_governance_declare_rejects_out_of_bounds(tmp_path) -> None:
    gov = WhiteTeam(registry=make_registry(), ledger_path=str(tmp_path / "l.jsonl"))
    try:
        gov.declare_scope("task-1", declared_by="white.sys-1", scope={"database": {}}, risk="yellow")
    except ScopeOutOfBoundsError:
        pass
    else:
        raise AssertionError("governance must refuse out-of-bounds scope")


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------

def test_secret_patterns_detected() -> None:
    assert scan_for_secrets("sk_live_0000000000000000") == ["sk_token"]
    assert scan_for_secrets("token ghp_ABCDEFGHIJKLMNOPQRST") == ["ghp_token"]
    assert "aws_access_key_id" in scan_for_secrets("AKIA0123456789ABCDEF")
    assert scan_for_secrets(PRIVATE_KEY) == ["private_key_header"]
    assert scan_for_secrets({"nested": ["plain", "sk_live_0000000000000000"]}) == ["sk_token"]
    assert scan_for_secrets("no secrets here") == []
    assert "credential_assignment" in scan_for_secrets("password=SuperSecret123!")
    assert "credential_assignment" in scan_for_secrets("PASSWORD = 'SuperSecret123!'")
    assert "credential_assignment" in scan_for_secrets({"config": ["api_key: abcdef0123456789"]})
    assert "credential_assignment" in scan_for_secrets("hmac_secret=ephemeral123")
    assert "credential_assignment" in scan_for_secrets("auth_token=ephemeral123")
    assert "credential_assignment" in scan_for_secrets("secret_value=ephemeral123")
    assert "credential_assignment" in scan_for_secrets("signing_key=ephemeral123")
    assert "credential_assignment" in scan_for_secrets("hmacSecret=ephemeral123")
    assert "credential_assignment" in scan_for_secrets("authToken=ephemeral123")
    assert "credential_assignment" in scan_for_secrets("secretValue=ephemeral123")
    assert scan_for_secrets("password reset required") == []
    assert scan_for_secrets("set password before login") == []
    assert scan_for_secrets("password_reset_required=true") == []


def test_raise_if_secret() -> None:
    raise_if_secret("clean")
    try:
        raise_if_secret({"key": PRIVATE_KEY})
    except SecretExposureError:
        pass
    else:
        raise AssertionError("secret-bearing payload must raise")


def test_ledger_rejects_secret_payload(tmp_path) -> None:
    ledger = EvidenceLedger(path=str(tmp_path / "l.jsonl"))
    try:
        ledger.append(
            "observation", actor="a", team="observer", source="s://",
            payload={"observation_type": "log", "detail": "ghp_ABCDEFGHIJKLMNOPQRST"},
        )
    except SecretExposureError:
        pass
    else:
        raise AssertionError("ledger must refuse secret material")
    assert len(ledger) == 0


def test_ledger_rejects_secret_source(tmp_path) -> None:
    ledger = EvidenceLedger()
    try:
        ledger.append(
            "observation", actor="a", team="observer",
            source=f"sk_live_0000000000000000://x",
            payload={"observation_type": "x", "detail": "d"},
        )
    except SecretExposureError:
        pass
    else:
        raise AssertionError("ledger must refuse secret-bearing source")


def test_coordinator_rejects_secret_at_intake(tmp_path) -> None:
    reg = make_registry()
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=WhiteTeam(registry=reg))
    result = c.create_task(
        title="deploy key", scope={"config": {"targets": ["app"]}},
        reason=f"using {PRIVATE_KEY}",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.SECRET_EXPOSURE.value
    assert c.event_count() == 0


def test_coordinator_rejects_secret_in_transition(tmp_path) -> None:
    reg = make_registry()
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=WhiteTeam(registry=reg))
    task = c.create_task(title="t", scope={"repo": "r"})
    result = c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason=f"sk_live_0000000000000000 leaked", evidence_refs=("x",),
        request_id="r-nope", action="read",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.SECRET_EXPOSURE.value


# ---------------------------------------------------------------------------
# Reviewer roles
# ---------------------------------------------------------------------------

def test_role_grant_revoke() -> None:
    reg = make_registry()
    assert reg.has_role("white.sys-1", "ci-operator")
    reg.revoke_role("white.sys-1", "ci-operator")
    assert not reg.has_role("white.sys-1", "ci-operator")


def test_unknown_role_rejected() -> None:
    reg = make_registry()
    try:
        reg.grant_role("white.sys-1", "root")
    except UnknownRoleError:
        pass
    else:
        raise AssertionError("unknown role must be rejected")


def test_role_team_restriction() -> None:
    reg = make_registry()
    try:
        reg.grant_role("silver.build-1", "ci-operator")
    except RoleNotAllowedError:
        pass
    else:
        raise AssertionError("silver team may not hold ci-operator")


# ---------------------------------------------------------------------------
# Approval roles, quorum, expiry
# ---------------------------------------------------------------------------

def _governed(tmp_path) -> tuple[Coordinator, WhiteTeam]:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "events.jsonl"), governance=gov)
    return c, gov


def test_yellow_tier_one_ci_operator_approval(tmp_path) -> None:
    c, gov = _governed(tmp_path)
    task = c.create_task(title="t", scope=DEV, risk="yellow")
    c.registry.grant_role("black.diag-1", "security-lead")
    c.registry.grant_role("white.sys-1", "platform-owner")
    gov.record_approval(task["task_id"], gated_action="release", approver="black.diag-1",
                        scope=DEV, approver_role="security-lead", author="silver.build-1")
    gov.record_approval(task["task_id"], gated_action="release", approver="white.sys-1",
                        scope=DEV, approver_role="platform-owner", author="silver.build-1")
    assert gov.has_valid_approval(task["task_id"], "release", requested_scope=DEV)


def test_default_ttl_is_ninety_days(tmp_path) -> None:
    c, gov = _governed(tmp_path)
    task = c.create_task(title="t", scope=DEV)
    approval = gov.record_approval(
        task["task_id"], gated_action="release", approver="white.sys-1", scope=DEV, author="silver.build-1",
    )
    assert approval.ttl_seconds == 90 * 24 * 3600
    assert approval.approver_role == "platform-owner"


def test_approver_without_role_rejected(tmp_path) -> None:
    c, gov = _governed(tmp_path)
    task = c.create_task(title="t", scope=DEV)
    try:
        gov.record_approval(
            task["task_id"], gated_action="release", approver="green.rel-1", scope=DEV, author="silver.build-1",
        )
    except RoleRequiredError:
        pass
    else:
        raise AssertionError("approver with no reviewer role must be refused")


def test_role_without_tier_authority_rejected(tmp_path) -> None:
    reg = make_registry()
    reg.grant_role("black.diag-1", "security-lead")
    gov = WhiteTeam(registry=reg)
    gov.declare_scope("task-y", declared_by="white.sys-1", scope=DEV, risk="yellow")
    try:
        gov.record_approval(
            "task-y", gated_action="read", approver="black.diag-1", scope=DEV, author="silver.build-1",
        )
    except RoleRiskForbidden:
        pass
    else:
        raise AssertionError(
            "security-lead must not clear a low-risk read gate"
        )


def test_ambiguous_roles_require_explicit_choice(tmp_path) -> None:
    reg = make_registry()
    reg.grant_role("white.sys-1", "platform-owner")
    reg.grant_role("white.sys-1", "security-lead")
    gov = WhiteTeam(registry=reg)
    gov.declare_scope("task-1", declared_by="white.sys-1", scope=DEV, risk="yellow")
    try:
        gov.record_approval(
            "task-1", gated_action="release", approver="white.sys-1", scope=DEV, author="silver.build-1",
        )
    except AmbiguousRoleError:
        pass
    else:
        raise AssertionError("two roles without explicit approver_role must be ambiguous")


def test_explicit_ambiguous_role_disambiguates(tmp_path) -> None:
    reg = make_registry()
    reg.grant_role("white.sys-1", "platform-owner")
    gov = WhiteTeam(registry=reg)
    gov.declare_scope("task-1", declared_by="white.sys-1", scope=DEV, risk="yellow")
    gov.record_approval(
        "task-1", gated_action="release", approver="white.sys-1", scope=DEV,
        approver_role="platform-owner", author="silver.build-1",
    )
    reg.grant_role("black.diag-1", "security-lead")
    gov.record_approval(
        "task-1", gated_action="release", approver="black.diag-1", scope=DEV,
        approver_role="security-lead", author="silver.build-1",
    )
    assert gov.has_valid_approval("task-1", "release", requested_scope=DEV)


def test_red_tier_requires_two_role_quorum(tmp_path) -> None:
    reg = make_registry()
    reg.grant_role("black.diag-1", "security-lead")
    reg.grant_role("white.sys-1", "platform-owner")
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    gov.declare_scope("task-r", declared_by="white.sys-1", scope=DEV, risk="red")

    lead = gov.record_approval(
        "task-r", gated_action="release", approver="black.diag-1", scope=DEV, author="silver.build-1",
    )
    assert not gov.has_valid_approval("task-r", "release", requested_scope=DEV)

    gov.record_approval(
        "task-r", gated_action="release", approver="white.sys-1", scope=DEV,
        approver_role="platform-owner", author="silver.build-1",
    )
    assert gov.approval_valid(lead.approval_id, "task-r", "release", DEV)
    assert gov.has_valid_approval("task-r", "release", requested_scope=DEV)


def test_approval_invalid_after_role_revoked(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg)
    gov.declare_scope("task-1", declared_by="white.sys-1", scope=DEV, risk="yellow")
    approval = gov.record_approval(
        "task-1", gated_action="release", approver="white.sys-1", scope=DEV, author="silver.build-1",
    )
    reg.revoke_role("white.sys-1", "ci-operator")
    assert not gov.approval_quorum_met("task-1", "release", requested_scope=DEV)
    assert not gov.has_valid_approval("task-1", "release", requested_scope=DEV)


# ---------------------------------------------------------------------------
# Idempotency fingerprints
# ---------------------------------------------------------------------------

def _make_event(task_id: str, actor: str, rid: str, reason: str, fp: str) -> Event:
    return Event(
        event_id="evt-x", task_id=task_id, correlation_id=f"corr-{task_id}",
        seq=1, request_id=rid, trigger=Trigger.ROUTE.value, actor=actor,
        timestamp="2026-09-18T00:00:00.000Z", reason=reason, outcome="SUCCESS",
        from_state=None, to_state=TaskState.OBSERVE.value, payload_fingerprint=fp,
    )


def test_replay_returns_cached_outcome() -> None:
    log = EventLog()
    fp1 = idempotency_fingerprint("route", "reason-a")
    first = log.append(_make_event("t1", "a", "rid-1", "reason-a", ""), fp1)
    assert log.seen("a", "rid-1", fp1) == first
    assert log.seen("a", "rid-1", fp1)["event"]["task_id"] == "t1"


def test_key_reuse_with_different_payload_is_conflict() -> None:
    log = EventLog()
    fp1 = idempotency_fingerprint("route", "reason-a")
    fp2 = idempotency_fingerprint("route", "reason-b")
    log.append(_make_event("t1", "a", "rid-1", "reason-a", ""), fp1)
    assert log.seen("a", "rid-1", fp2) is IDEMPOTENCY_CONFLICT


def test_event_log_rejects_tampered_tail(tmp_path) -> None:
    import pytest
    path = tmp_path / "events.jsonl"
    log = EventLog(str(path))
    log.append(_make_event("t1", "a", "rid-1", "reason-a", ""))
    rows = path.read_text(encoding="utf-8").splitlines()
    import json
    event = json.loads(rows[0])
    event["reason"] = "rewritten"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    from colorharness.eventlog import CorruptEventStoreError
    with pytest.raises(CorruptEventStoreError):
        EventLog(str(path))


def test_coordinator_rejects_idempotency_conflict(tmp_path) -> None:
    reg = make_registry()
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), governance=WhiteTeam(registry=reg))
    task = c.create_task(title="t", scope={"repo": "r"})
    c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="route me", evidence_refs=("x",), request_id="rid-route",
    )
    before = c.event_count()
    conflict = c.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="a totally different reason", evidence_refs=("y",), request_id="rid-route",
    )
    assert conflict["success"] is False
    assert conflict["error"]["code"] == RejectionCode.IDEMPOTENCY_CONFLICT.value
    assert c.event_count() == before


def test_replayed_transition_after_restart_returns_cached(tmp_path) -> None:
    reg = make_registry()
    store = str(tmp_path / "e.jsonl")
    gov1 = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger-replay.jsonl"))
    c1 = Coordinator(registry=reg, store_path=store, governance=gov1)
    task = c1.create_task(title="t", scope={"repo": "r"})
    c1.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="route me", evidence_refs=("x",), request_id="rid-route",
    )
    count = c1.event_count()
    gov2 = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger-replay.jsonl"))
    c2 = Coordinator(registry=reg, store_path=store, governance=gov2)
    replay = c2.apply_transition(
        task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
        reason="route me", evidence_refs=("x",), request_id="rid-route",
    )
    assert replay["success"] is True
    assert c2.event_count() == count


# ---------------------------------------------------------------------------
# Watchdog: quarantine + stale-block escalation
# ---------------------------------------------------------------------------

def test_watchdog_heartbeat_and_staleness(tmp_path) -> None:
    reg = make_registry()
    reg.register("y", "blue")
    wd = Watchdog(now_fn=lambda: 1_000.0)
    Coordinator(registry=reg, governance=WhiteTeam(
        registry=reg, ledger_path=str(tmp_path / "ledger.jsonl")
    ), watchdog=wd)
    assert wd.last_heartbeat("y") is None
    assert wd.missed_heartbeats("y") == HEARTBEAT_MISSES_THRESHOLD + 1
    wd.heartbeat("y", actor="y", now=1_000.0)
    assert wd.missed_heartbeats("y", now=1_000.0) == 0
    assert wd.missed_heartbeats("y", now=1_000.0 + 3 * 60) == 2
    assert wd.is_stale("y", now=1_000.0 + 4 * 60)


def test_quarantined_agent_rejected(tmp_path) -> None:
    wd = Watchdog()
    reg = make_registry()
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"), watchdog=wd,
                    governance=WhiteTeam(registry=reg, ledger_path=str(tmp_path / "ledger.jsonl")))
    task = c.create_task(title="t", scope={"repo": "r"})
    c.apply_transition(task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("x",), request_id="r-route")
    wd.quarantine("blue.obs-1", actor="white.sys-1", reason="runaway loop")
    result = c.apply_transition(
        task["task_id"], Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
        reason="obs", evidence_refs=("x",), request_id="r-obs",
    )
    assert result["success"] is False
    assert result["error"]["code"] == RejectionCode.AGENT_QUARANTINED.value
    assert c.get_task(task["task_id"])["state"] == TaskState.OBSERVE.value


def test_watchdog_auto_quarantines_stale_actor_and_restores_from_ledger(tmp_path) -> None:
    now = [1_000.0]
    reg = make_registry()
    ledger_path = str(tmp_path / "ledger.jsonl")
    store_path = str(tmp_path / "events.jsonl")
    gov = WhiteTeam(registry=reg, ledger_path=ledger_path)
    wd = Watchdog(now_fn=lambda: now[0])
    c = Coordinator(registry=reg, store_path=store_path, governance=gov, watchdog=wd)
    task = c.create_task(title="watchdog", scope={"repo": "r"})
    c.apply_transition(task["task_id"], Trigger.ROUTE, actor=Coordinator.SYSTEM_AGENT,
                       reason="route", evidence_refs=("x",), request_id="r-route")
    wd.heartbeat("blue.obs-1", actor="blue.obs-1", now=now[0])
    now[0] += 4 * 60

    result = c.apply_transition(
        task["task_id"], Trigger.OBSERVATIONS_READY, actor="blue.obs-1",
        reason="stale actor", evidence_refs=("x",), request_id="r-stale",
    )
    assert result["error"]["code"] == RejectionCode.AGENT_QUARANTINED.value
    assert wd.is_quarantined("blue.obs-1")
    quarantine_records = [
        r for r in gov.ledger.records
        if r.record_type == "decision" and r.payload.get("decision_type") == "watchdog_quarantine"
    ]
    assert quarantine_records

    wd2 = Watchdog(now_fn=lambda: now[0])
    gov2 = WhiteTeam(registry=reg, ledger_path=ledger_path)
    Coordinator(registry=reg, store_path=store_path, governance=gov2, watchdog=wd2)
    assert wd2.is_quarantined("blue.obs-1")
    with pytest.raises(GovernanceError):
        wd2.unquarantine("blue.obs-1", actor="red.tar-1")
    assert wd2.is_quarantined("blue.obs-1")
    with pytest.raises(GovernanceError):
        wd2.heartbeat("blue.obs-1", actor="red.tar-1", now=now[0])
    wd2.unquarantine("blue.obs-1", actor="white.sys-1", reason="recovery reviewed")
    assert not wd2.is_quarantined("blue.obs-1")
    wd3 = Watchdog(now_fn=lambda: now[0])
    gov3 = WhiteTeam(registry=reg, ledger_path=ledger_path)
    Coordinator(registry=reg, store_path=store_path, governance=gov3, watchdog=wd3)
    assert not wd3.is_quarantined("blue.obs-1")


def test_watchdog_escalates_stale_block(tmp_path) -> None:
    reg = make_registry()
    gov = WhiteTeam(registry=reg, ledger_path=str(tmp_path / "l.jsonl"))
    c = Coordinator(registry=reg, store_path=str(tmp_path / "e.jsonl"),
                    governance=gov, watchdog=Watchdog())
    task = c.create_task(title="t", scope={"repo": "r"})
    for trigger, actor, reason in FULL_PATH:
        if TaskState(c.get_task(task["task_id"])["state"]) == TaskState.DIAGNOSE:
            break
        refs = _record_gate_evidence(c, task["task_id"], trigger)
        c.apply_transition(task["task_id"], trigger, actor=actor, reason=reason,
                           evidence_refs=refs or (f"log://{reason}",),
                           request_id=f"rid-{reason}-{actor}")
    c.apply_transition(task["task_id"], Trigger.BLOCK, actor="black.diag-1",
                       reason="stale artifact", evidence_refs=("log://block",),
                       request_id="rid-block")
    assert c.get_task(task["task_id"])["state"] == TaskState.BLOCKED.value

    entered = {
        task["task_id"]: c.state_entered_at(task["task_id"]).get(TaskState.BLOCKED.value)
    }
    baseline = time.time()
    wd = Watchdog(now_fn=lambda: baseline + 1000)
    escalated = wd.escalate_stale_blocks(gov, entered)
    assert escalated == [task["task_id"]]
    decisions = [r for r in gov.ledger.records if r.record_type == "decision"]
    assert decisions and decisions[-1].payload["decision_type"] == "escalation"
    assert decisions[-1].actor == WATCHDOG_AGENT


# ---------------------------------------------------------------------------
# Ledger manifest digest
# ---------------------------------------------------------------------------

def test_manifest_digest_anchors_ledger() -> None:
    ledger = EvidenceLedger()
    ledger.append("observation", actor="a", team="observer", source="s://",
                  payload={"observation_type": "x", "detail": "m1"}, task_id="t1")
    digest1 = ledger.manifest_digest()
    assert not ledger.verify_manifest()
    assert ledger.verify_manifest(digest1)
    assert len(digest1) == 64

    ledger.append("observation", actor="b", team="observer", source="s://",
                  payload={"observation_type": "x", "detail": "m2"}, task_id="t2")
    assert ledger.manifest_digest() != digest1
    assert ledger.verify_manifest(digest1) is False


def test_manifest_detects_tampering() -> None:
    ledger = EvidenceLedger()
    ledger.append("observation", actor="a", team="observer", source="s://",
                  payload={"observation_type": "x", "detail": "m1"}, task_id="t1")
    ledger.append("observation", actor="b", team="observer", source="s://",
                  payload={"observation_type": "x", "detail": "m2"}, task_id="t2")
    anchor = ledger.manifest_digest()
    assert ledger.verify_manifest(anchor)
    tampered = ledger.records[0]
    object.__setattr__(tampered, "payload", {"observation_type": "x", "detail": "evil"})
    assert ledger.manifest_digest() != anchor
    assert ledger.verify_manifest(anchor) is False
    assert ledger.verify_chain() is False
