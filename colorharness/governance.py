"""White Team governance: scope declarations, approvals, risk classification,
pause/escalation, evidence ledger, and append-only audit output."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ._common import APPROVAL_TTL_SECONDS, Trigger, now_utc_iso
from .black import Diagnosis, Experiment, Hypothesis
from .eventlog import Event
from .ledger import EvidenceLedger, EvidenceRecord
from .observer import FORBIDDEN_INTERPRETATION_KEYS, Observation
from .registry import APPROVER_ROLES, TeamRegistry
from .risk import RiskClass, is_higher, normalize
from .scope import ScopeOutOfBoundsError, validate_scope

GOVERNED_ACTIONS: dict[Trigger, str] = {
    Trigger.RELEASE_APPROVED: "release",
    Trigger.ROLLBACK_INITIATED: "rollback",
}

PROTECTED_ACTIONS: frozenset[str] = frozenset(
    {"release", "rollback", "destructive_delete", "credential_rotation",
     "security_control_change", "scope_expansion", "production_deploy"}
)

AUDIT_TYPES: frozenset[str] = frozenset(
    {"approval", "decision", "scope_declaration", "pause", "transition"}
)

# Minimum approval authority required to clear a given risk tier. Red requires
# both roles *and* two distinct approvers; orange requires a security-lead;
# green/yellow require a ci-operator.
RISK_AUTHORITY: dict[str, frozenset[str]] = {
    "green": frozenset({"ci-operator"}),
    "yellow": frozenset({"ci-operator"}),
    "orange": frozenset({"security-lead"}),
    "red": frozenset({"security-lead", "platform-owner"}),
}

QUORUM_COUNT: dict[str, int] = {"green": 1, "yellow": 1, "orange": 1, "red": 2}


class GovernanceError(Exception):
    pass


class NoSelfApprovalError(GovernanceError):
    pass


class ScopeApprovalRequired(GovernanceError):
    pass


class RiskRegressionError(GovernanceError):
    pass


class ScopeNotDeclaredError(GovernanceError):
    pass


class RoleRequiredError(GovernanceError):
    pass


class AmbiguousRoleError(GovernanceError):
    pass


class RoleRiskForbidden(GovernanceError):
    pass


class InterpretationNotRecordedError(GovernanceError):
    pass


def scope_covers(granted: dict, requested: dict) -> bool:
    for key, wanted in requested.items():
        if key not in granted:
            return False
        have = granted[key]
        if isinstance(wanted, (list, tuple, set, frozenset)):
            if not isinstance(have, (list, tuple, set, frozenset)):
                return False
            if not set(wanted) <= set(have):
                return False
        elif have != wanted:
            return False
    return True


@dataclass(frozen=True)
class ScopeDeclaration:
    task_id: str
    declared_by: str
    scope: dict
    risk: RiskClass
    correlation_id: Optional[str]
    created_at: str
    evidence_id: str
    version: int = 1


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    task_id: str
    gated_action: str
    approver: str
    approver_team: str
    approver_role: str
    scope: dict
    issued_at: str
    issued_epoch: float
    ttl_seconds: int
    evidence_id: str
    expires_at_epoch: float
    expires_at: str
    revoked: bool = False


@dataclass(frozen=True)
class PauseRecord:
    task_id: str
    actor: str
    reason: str
    evidence_id: str
    timestamp: str


class WhiteTeam:
    def __init__(
        self,
        ledger: Optional[EvidenceLedger] = None,
        ledger_path: Optional[str] = None,
        registry: Optional[TeamRegistry] = None,
    ):
        self.ledger = ledger or EvidenceLedger(path=ledger_path)
        self.registry = registry
        self._scopes: dict[str, ScopeDeclaration] = {}
        self._approvals: dict[str, ApprovalRecord] = {}
        self._revoked: set[str] = set()
        self._paused: dict[str, PauseRecord] = {}
        self._rebuild_from_ledger()

    def _rebuild_from_ledger(self) -> None:
        versions: dict[str, int] = {}
        for record in self.ledger.records:
            if record.task_id is None:
                continue
            payload = record.payload or {}
            if record.record_type == "scope_declaration":
                versions[record.task_id] = versions.get(record.task_id, 0) + 1
                self._scopes[record.task_id] = ScopeDeclaration(
                    task_id=record.task_id,
                    declared_by=payload.get("declared_by", record.actor),
                    scope=dict(payload.get("scope", {})),
                    risk=normalize(payload.get("risk", RiskClass.YELLOW)),
                    correlation_id=record.correlation_id,
                    created_at=record.timestamp,
                    evidence_id=record.evidence_id,
                    version=versions[record.task_id],
                )
            elif record.record_type == "approval":
                approval = ApprovalRecord(
                    approval_id=payload.get("approval_id", record.evidence_id),
                    task_id=record.task_id,
                    gated_action=payload.get("gated_action", ""),
                    approver=payload.get("approver", record.actor),
                    approver_team=payload.get("approver_team", "unknown"),
                    approver_role=payload.get("approver_role", ""),
                    scope=dict(payload.get("scope", {})),
                    issued_at=record.timestamp,
                    issued_epoch=float(payload.get("issued_epoch", 0.0)),
                    ttl_seconds=int(payload.get("ttl_seconds", 0)),
                    evidence_id=record.evidence_id,
                    expires_at_epoch=float(payload.get("expires_at_epoch", 0.0)),
                    expires_at=payload.get("expiry", ""),
                )
                self._approvals[approval.approval_id] = approval
            elif record.record_type == "decision":
                if payload.get("decision_type") == "approval_revoked":
                    scope = payload.get("scope", {})
                    approval_id = scope.get("approval_id")
                    if approval_id:
                        self._revoked.add(approval_id)
                elif payload.get("decision_type") == "pause_lifted":
                    self._paused.pop(record.task_id, None)
            elif record.record_type == "pause":
                self._paused[record.task_id] = PauseRecord(
                    task_id=record.task_id,
                    actor=payload.get("actor", record.actor),
                    reason=payload.get("reason", ""),
                    evidence_id=record.evidence_id,
                    timestamp=record.timestamp,
                )

    # ------------------------------------------------------------------
    # Scope declarations
    # ------------------------------------------------------------------

    def declare_scope(
        self,
        task_id: str,
        *,
        declared_by: str,
        scope: dict,
        risk: RiskClass | str,
        correlation_id: Optional[str] = None,
    ) -> ScopeDeclaration:
        risk_cls = normalize(risk)
        validate_scope(dict(scope))
        record = self.ledger.append(
            "scope_declaration",
            actor=declared_by,
            team="white",
            source="governance://declare_scope",
            payload={
                "declared_by": declared_by,
                "scope": dict(scope),
                "risk": risk_cls.value,
            },
            task_id=task_id,
            correlation_id=correlation_id,
        )
        decl = ScopeDeclaration(
            task_id=task_id,
            declared_by=declared_by,
            scope=dict(scope),
            risk=risk_cls,
            correlation_id=correlation_id,
            created_at=record.timestamp,
            evidence_id=record.evidence_id,
            version=1,
        )
        self._scopes[task_id] = decl
        return decl

    def get_scope(self, task_id: str) -> Optional[ScopeDeclaration]:
        return self._scopes.get(task_id)

    def expand_scope(
        self,
        task_id: str,
        *,
        additions: dict,
        actor: str,
        approval_id: Optional[str] = None,
    ) -> ScopeDeclaration:
        current = self._scopes.get(task_id)
        if current is None:
            raise ScopeNotDeclaredError(f"no scope declared for task '{task_id}'")
        merged: dict = {k: list(v) if isinstance(v, (list, tuple, set)) else v
                        for k, v in current.scope.items()}
        for key, value in additions.items():
            if key in merged and isinstance(merged[key], list) and isinstance(value, (list, tuple, set)):
                merged[key] = sorted(set(merged[key]) | set(value))
            else:
                merged[key] = list(value) if isinstance(value, (list, tuple, set)) else value

        validate_scope(merged)

        if approval_id is None or not self.approval_valid(
            approval_id, task_id, "scope_expansion", merged
        ):
            raise ScopeApprovalRequired(
                f"scope expansion for task '{task_id}' requires a valid "
                "'scope_expansion' approval covering the expanded scope"
            )

        record = self.ledger.append(
            "scope_declaration",
            actor=actor,
            team="white",
            source="governance://expand_scope",
            payload={
                "declared_by": actor,
                "scope": dict(merged),
                "risk": current.risk.value,
            },
            task_id=task_id,
            correlation_id=current.correlation_id,
            refs=(current.evidence_id,),
        )
        declaration = ScopeDeclaration(
            task_id=task_id,
            declared_by=actor,
            scope=dict(merged),
            risk=current.risk,
            correlation_id=current.correlation_id,
            created_at=record.timestamp,
            evidence_id=record.evidence_id,
            version=current.version + 1,
        )
        self._scopes[task_id] = declaration
        return declaration

    # ------------------------------------------------------------------
    # Risk classification
    # ------------------------------------------------------------------

    def current_risk(self, task_id: str) -> RiskClass:
        scope = self._scopes.get(task_id)
        if scope is None:
            return RiskClass.YELLOW
        return scope.risk

    def raise_risk(
        self,
        task_id: str,
        *,
        risk: RiskClass | str,
        actor: str,
        reason: str,
    ) -> RiskClass:
        new_risk = normalize(risk)
        current = self.current_risk(task_id)
        if not is_higher(new_risk, current) and new_risk != current:
            raise RiskRegressionError(
                f"risk for task '{task_id}' is '{current.value}'; "
                f"cannot lower it to '{new_risk.value}'"
            )
        if new_risk != current:
            self.ledger.append(
                "decision",
                actor=actor,
                team="white",
                source="governance://raise_risk",
                payload={
                    "decision_type": "risk_reclassification",
                    "decider": actor,
                    "reasoning": reason,
                    "scope": {"task_id": task_id, "risk": new_risk.value},
                },
                task_id=task_id,
            )
            scope = self._scopes[task_id]
            self._scopes[task_id] = ScopeDeclaration(
                task_id=scope.task_id,
                declared_by=scope.declared_by,
                scope=dict(scope.scope),
                risk=new_risk,
                correlation_id=scope.correlation_id,
                created_at=scope.created_at,
                evidence_id=scope.evidence_id,
                version=scope.version,
            )
        return new_risk

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def record_approval(
        self,
        task_id: str,
        *,
        gated_action: str,
        approver: str,
        scope: dict,
        ttl_seconds: Optional[int] = None,
        author: Optional[str] = None,
        approver_role: Optional[str] = None,
    ) -> ApprovalRecord:
        if author is not None and approver == author:
            raise NoSelfApprovalError(
                f"approver '{approver}' is the author of the change and may not approve it"
            )
        role = self._resolve_approver_role(approver, approver_role, task_id)

        approved_team = "unknown"
        if self.registry is not None and self.registry.is_registered(approver):
            approved_team = self.registry.team_of(approver)

        ttl = APPROVAL_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
        issued_epoch = time.time()
        now_str = now_utc_iso()
        expires_epoch = issued_epoch + ttl
        expires_dt = datetime.fromtimestamp(expires_epoch, tz=timezone.utc)
        expires_str = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        approval_id = f"apr-{uuid.uuid4().hex[:12]}"
        record = self.ledger.append(
            "approval",
            actor=approver,
            team="white",
            source="governance://record_approval",
            payload={
                "approval_id": approval_id,
                "approver": approver,
                "approver_team": approved_team,
                "approver_role": role,
                "scope": dict(scope),
                "expiry": expires_str,
                "gated_action": gated_action,
                "decision_id": f"dec-{uuid.uuid4()}",
                "ttl_seconds": ttl,
                "issued_epoch": issued_epoch,
                "expires_at_epoch": expires_epoch,
            },
            task_id=task_id,
        )
        approval = ApprovalRecord(
            approval_id=approval_id,
            task_id=task_id,
            gated_action=gated_action,
            approver=approver,
            approver_team=approved_team,
            approver_role=role,
            scope=dict(scope),
            issued_at=now_str,
            issued_epoch=issued_epoch,
            ttl_seconds=ttl,
            evidence_id=record.evidence_id,
            expires_at_epoch=expires_epoch,
            expires_at=expires_str,
        )
        self._approvals[approval.approval_id] = approval
        return approval

    def _resolve_approver_role(
        self,
        approver: str,
        explicit: Optional[str],
        task_id: str,
    ) -> str:
        if explicit is not None:
            if explicit not in APPROVER_ROLES:
                from .registry import UnknownRoleError
                raise UnknownRoleError(f"unknown reviewer role '{explicit}'")
            role = explicit
        else:
            if self.registry is None:
                raise RoleRequiredError(
                    "approver_role is required when no registry is configured"
                )
            held = APPROVER_ROLES & self.registry.role_of(approver)
            if not held:
                raise RoleRequiredError(
                    f"approver '{approver}' holds no reviewer role"
                )
            if len(held) > 1:
                raise AmbiguousRoleError(
                    f"approver '{approver}' holds multiple roles {sorted(held)}; "
                    "pass approver_role explicitly"
                )
            role = next(iter(held))
        if self.registry is not None and not self.registry.has_role(approver, role):
            raise RoleRequiredError(
                f"approver '{approver}' does not hold role '{role}'"
            )
        risk = self.current_risk(task_id).value
        if role not in RISK_AUTHORITY[risk]:
            raise RoleRiskForbidden(
                f"role '{role}' has no approval authority over {risk}-tier task '{task_id}'"
            )
        return role

    def revoke_approval(
        self,
        approval_id: str,
        *,
        actor: str,
        reason: str,
    ) -> None:
        approval = self._approvals[approval_id]
        self._revoked.add(approval_id)
        self.ledger.append(
            "decision",
            actor=actor,
            team="white",
            source="governance://revoke_approval",
            payload={
                "decision_type": "approval_revoked",
                "decider": actor,
                "reasoning": reason,
                "scope": {"approval_id": approval_id, "task_id": approval.task_id},
            },
            task_id=approval.task_id,
            refs=(approval.evidence_id,),
        )

    def approvals_for(self, task_id: str) -> list[ApprovalRecord]:
        return [a for a in self._approvals.values() if a.task_id == task_id]

    def approval_valid(
        self,
        approval_id: str,
        task_id: str,
        gated_action: str,
        requested_scope: Optional[dict] = None,
        *,
        now_epoch: Optional[float] = None,
    ) -> bool:
        approval = self._approvals.get(approval_id)
        if approval is None:
            return False
        if approval.task_id != task_id:
            return False
        if approval.gated_action not in (gated_action, "*"):
            return False
        if approval_id in self._revoked:
            return False
        at = now_epoch if now_epoch is not None else time.time()
        if at >= approval.expires_at_epoch:
            return False
        if requested_scope is not None and not scope_covers(approval.scope, requested_scope):
            return False
        return True

    def has_valid_approval(
        self,
        task_id: str,
        gated_action: str,
        *,
        requested_scope: Optional[dict] = None,
        now_epoch: Optional[float] = None,
    ) -> bool:
        return self.approval_quorum_met(
            task_id,
            gated_action,
            requested_scope=requested_scope,
            now_epoch=now_epoch,
        )

    def approval_quorum_met(
        self,
        task_id: str,
        gated_action: str,
        *,
        requested_scope: Optional[dict] = None,
        now_epoch: Optional[float] = None,
    ) -> bool:
        """True when valid approvals satisfy the task risk tier's quorum:
        all required roles present (red = security-lead + platform-owner)
        and enough distinct approvers (red = 2, else 1).
        """
        risk = self.current_risk(task_id).value
        required_roles = RISK_AUTHORITY[risk]
        quorum = QUORUM_COUNT[risk]
        covered_roles: set[str] = set()
        approvers: set[str] = set()
        for approval in self._approvals.values():
            if not self.approval_valid(
                approval.approval_id,
                task_id,
                gated_action,
                requested_scope,
                now_epoch=now_epoch,
            ):
                continue
            if not approval.approver_role:
                continue
            if (
                self.registry is not None
                and not self.registry.has_role(approval.approver, approval.approver_role)
            ):
                continue
            covered_roles.add(approval.approver_role)
            approvers.add(approval.approver)
        return required_roles <= covered_roles and len(approvers) >= quorum

    def require_approval(
        self,
        task_id: str,
        gated_action: str,
        *,
        requested_scope: Optional[dict] = None,
    ) -> ApprovalRecord | None:
        for approval in self._approvals.values():
            if self.approval_valid(
                approval.approval_id, task_id, gated_action, requested_scope
            ):
                return approval
        return None

    # ------------------------------------------------------------------
    # Pause / escalation
    # ------------------------------------------------------------------

    def pause(
        self,
        task_id: str,
        *,
        actor: str,
        reason: str,
    ) -> PauseRecord:
        record = self.ledger.append(
            "pause",
            actor=actor,
            team="white",
            source="governance://pause",
            payload={"actor": actor, "reason": reason},
            task_id=task_id,
        )
        pause = PauseRecord(
            task_id=task_id,
            actor=actor,
            reason=reason,
            evidence_id=record.evidence_id,
            timestamp=record.timestamp,
        )
        self._paused[task_id] = pause
        return pause

    def resume(
        self,
        task_id: str,
        *,
        actor: str,
        reason: str,
    ) -> None:
        if task_id not in self._paused:
            return
        paused = self._paused.pop(task_id)
        self.ledger.append(
            "decision",
            actor=actor,
            team="white",
            source="governance://resume",
            payload={
                "decision_type": "pause_lifted",
                "decider": actor,
                "reasoning": reason,
                "scope": {"task_id": task_id},
            },
            task_id=task_id,
            refs=(paused.evidence_id,),
        )

    def is_paused(self, task_id: str) -> bool:
        return task_id in self._paused

    def escalate(
        self,
        task_id: str,
        *,
        actor: str,
        reason: str,
        decision_ref: Optional[str] = None,
    ) -> None:
        self.ledger.append(
            "decision",
            actor=actor,
            team="white",
            source="governance://escalate",
            payload={
                "decision_type": "escalation",
                "decider": actor,
                "reasoning": reason,
                "scope": {"task_id": task_id},
            },
            task_id=task_id,
            correlation_id=self._correlation_for(task_id),
            refs=(decision_ref,) if decision_ref else (),
        )

    # ------------------------------------------------------------------
    # Transition interop
    # ------------------------------------------------------------------

    def record_transition(self, event: Event) -> None:
        self.ledger.append(
            "transition",
            actor=event.actor,
            team="coordinator",
            source=f"coordinator://transition/{event.event_id}",
            payload={
                "previous_state": event.from_state,
                "new_state": event.to_state,
                "trigger": event.trigger,
                "reason_code": "NONE",
            },
            task_id=event.task_id,
            correlation_id=event.correlation_id,
            agent_id=event.actor,
            refs=tuple(event.evidence_refs),
            event_id=event.event_id,
        )

    # ------------------------------------------------------------------
    # Observer / Blue write paths (governed by White)
    # ------------------------------------------------------------------

    def record_observations(
        self,
        task_id: str,
        observations: tuple[Observation, ...],
        *,
        actor: str = "white.sys-1",
        team: str = "white",
    ) -> list[EvidenceRecord]:
        """Record collected facts as observation evidence. White owns the write;
        the observer itself holds no ledger handle."""
        records: list[EvidenceRecord] = []
        for obs in observations:
            forbidden = set(obs.detail) & FORBIDDEN_INTERPRETATION_KEYS
            if forbidden:
                raise InterpretationNotRecordedError(
                    f"observation '{obs.observation_id}' carries interpretation "
                    f"keys {sorted(forbidden)}; facts and interpretations are "
                    "stored separately"
                )
            record = self.ledger.append(
                "observation",
                actor=actor,
                team=team,
                source=obs.source,
                payload=obs.payload(),
                task_id=task_id,
                correlation_id=obs.correlation_id,
                refs=(obs.observation_id,),
            )
            records.append(record)
        return records

    def record_blue_output(
        self,
        task_id: str,
        outputs: tuple,
        *,
        actor: str = "white.sys-1",
        team: str = "white",
    ) -> list[EvidenceRecord]:
        """Record blue-team interpretations (alerts, recommendations, runbook
        entries) as evidence so they are auditable and attributable."""
        records: list[EvidenceRecord] = []
        for output in outputs:
            kind = type(output).__name__.lower()
            if kind == "alert":
                payload: dict[str, Any] = {
                    "alert_id": output.alert_id,
                    "metric": output.metric,
                    "observed_value": output.observed_value,
                    "threshold": output.threshold,
                    "severity": output.severity,
                    "observation_refs": list(output.observation_refs),
                }
                record_type = "alert"
            elif kind == "recommendation":
                payload = {
                    "recommendation_id": output.recommendation_id,
                    "recommended_action": output.recommended_action,
                    "rationale": output.rationale,
                    "severity": output.severity,
                    "evidence_refs": list(output.evidence_refs),
                }
                record_type = "recommendation"
            elif kind == "runbookentry":
                payload = {
                    "entry_id": output.entry_id,
                    "procedure": output.procedure,
                    "severity": output.severity,
                    "source_refs": list(output.source_refs),
                }
                record_type = "runbook_entry"
            else:
                raise GovernanceError(
                    f"unsupported blue output type '{kind}'"
                )
            records.append(
                self.ledger.append(
                    record_type,
                    actor=actor,
                    team=team,
                    source=f"blue://{output.__class__.__name__}",
                    payload=payload,
                    task_id=task_id,
                    refs=tuple(
                        getattr(output, "evidence_refs", ())
                        or getattr(output, "observation_refs", ())
                        or getattr(output, "source_refs", ())
                    ),
                )
            )
        return records

    def record_black_output(
        self,
        task_id: str,
        outputs: tuple,
        *,
        actor: str = "white.sys-1",
        team: str = "white",
    ) -> list[EvidenceRecord]:
        """Record black-team interpretations (hypotheses, experiments,
        diagnoses) as evidence so they are attributable and auditable."""
        records: list[EvidenceRecord] = []
        for output in outputs:
            if isinstance(output, Hypothesis):
                payload: dict[str, Any] = {
                    "hypothesis_id": output.hypothesis_id,
                    "hypothesis": output.hypothesis,
                    "confidence": output.confidence,
                    "alternatives": list(output.alternatives),
                    "discriminator": output.discriminator,
                    "evidence_refs": list(output.evidence_refs),
                }
                record_type = "hypothesis"
            elif isinstance(output, Experiment):
                payload = {
                    "experiment_id": output.experiment_id,
                    "setup": dict(output.setup),
                    "inputs_ref": output.inputs_ref,
                    "result_ref": output.result_ref,
                    "verified": output.verified,
                }
                record_type = "experiment"
            elif isinstance(output, Diagnosis):
                payload = {
                    "diagnosis_id": output.diagnosis_id,
                    "diagnosis": output.diagnosis,
                    "confidence": output.confidence,
                    "evidence_refs": list(output.evidence_refs),
                    "alternatives": list(output.alternatives),
                }
                record_type = "diagnosis"
            else:
                raise GovernanceError(
                    f"unsupported black output type '{output.__class__.__name__}'"
                )
            records.append(
                self.ledger.append(
                    record_type,
                    actor=actor,
                    team=team,
                    source=f"black://{output.__class__.__name__}",
                    payload=payload,
                    task_id=task_id,
                    refs=tuple(
                        getattr(output, "evidence_refs", ())
                        or (getattr(output, "inputs_ref", ""),)
                    ),
                )
            )
        return records

    def has_evidence(self, task_id: str, record_type: str) -> bool:
        """True when at least one evidence record of ``record_type`` exists for
        the task. Used by the coordinator's evidence gates."""
        return any(
            r.task_id == task_id and r.record_type == record_type
            for r in self.ledger.records
        )

    # ------------------------------------------------------------------
    # Audit output
    # ------------------------------------------------------------------

    def _correlation_for(self, task_id: str) -> Optional[str]:
        scope = self._scopes.get(task_id)
        return scope.correlation_id if scope else None

    def audit_entries(self) -> list:
        return [r for r in self.ledger.records if r.record_type in AUDIT_TYPES]

    def write_audit(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for record in self.audit_entries():
                fh.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
                fh.flush()

    def verify(self) -> bool:
        return self.ledger.verify_chain()