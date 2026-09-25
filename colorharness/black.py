"""Black Team: deep diagnostics — hypotheses, controlled experiments, diagnosis.

Black consumes recorded observations and produces *interpretations* that must
cite the evidence they are based on. A diagnosis without uncertainty is a claim,
not a diagnosis: every ``Diagnosis`` therefore carries alternatives and a
confidence level (Low | Medium | High). Black output is persisted as evidence by
the white team (``WhiteTeam.record_black_output``); Black itself holds no ledger
handle.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from ._common import now_utc_iso

CONFIDENCE_LEVELS: frozenset[str] = frozenset({"low", "medium", "high"})


class BlackTeamError(Exception):
    pass


class BlackNoEvidenceError(BlackTeamError):
    pass


class BlackNoUncertaintyError(BlackTeamError):
    pass


class BlackUnauthorizedActorError(BlackTeamError):
    pass


class InvalidInputError(BlackTeamError):
    pass


@dataclass(frozen=True)
class Hypothesis:
    """A testable candidate explanation, with alternatives and confidence."""

    hypothesis_id: str
    task_id: str
    actor: str
    hypothesis: str
    confidence: str
    alternatives: tuple[str, ...]
    discriminator: str
    evidence_refs: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        if not self.hypothesis.strip():
            raise InvalidInputError("a hypothesis needs text")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise InvalidInputError(
                f"confidence must be one of {sorted(CONFIDENCE_LEVELS)}"
            )
        if not self.alternatives:
            raise BlackNoUncertaintyError(
                "a hypothesis without alternatives has no discriminator to test"
            )
        if not self.discriminator.strip():
            raise InvalidInputError("a hypothesis needs a discriminator")
        if not self.evidence_refs:
            raise BlackNoEvidenceError(
                "a hypothesis must cite the evidence it is based on"
            )


@dataclass(frozen=True)
class Experiment:
    """A controlled experiment that returns a verdict on a hypothesis."""

    experiment_id: str
    task_id: str
    actor: str
    setup: dict
    inputs_ref: str
    result_ref: str
    verified: bool
    timestamp: str

    def __post_init__(self) -> None:
        if not self.setup:
            raise InvalidInputError("an experiment needs a setup")
        if not self.inputs_ref or not self.result_ref:
            raise BlackNoEvidenceError(
                "an experiment must cite its inputs and its result"
            )


@dataclass(frozen=True)
class Diagnosis:
    """An evidence-based explanation, with uncertainty made visible."""

    diagnosis_id: str
    task_id: str
    actor: str
    diagnosis: str
    confidence: str
    evidence_refs: tuple[str, ...]
    alternatives: tuple[str, ...]
    timestamp: str

    def __post_init__(self) -> None:
        if not self.diagnosis.strip():
            raise InvalidInputError("a diagnosis needs text")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise InvalidInputError(
                f"confidence must be one of {sorted(CONFIDENCE_LEVELS)}"
            )
        if not self.evidence_refs:
            raise BlackNoEvidenceError(
                "a diagnosis must cite the evidence it is based on"
            )
        if not self.alternatives:
            raise BlackNoUncertaintyError(
                "a diagnosis without uncertainty is a claim, not a diagnosis"
            )


class BlackTeam:
    BLACK_ID = "black.diag-1"

    def __init__(self, registry=None):
        self.registry = registry

    def _check_actor(self, actor: str) -> None:
        if self.registry is None or not self.registry.is_registered(actor):
            raise BlackUnauthorizedActorError(f"actor '{actor}' is not registered")
        if self.registry.team_of(actor) != "black":
            raise BlackUnauthorizedActorError(
                f"actor '{actor}' is not a black team agent"
            )

    def hypothesize(
        self,
        task_id: str,
        *,
        actor: str,
        hypothesis: str,
        confidence: str = "low",
        alternatives: tuple[str, ...],
        discriminator: str,
        evidence_refs: tuple[str, ...],
    ) -> Hypothesis:
        self._check_actor(actor)
        return Hypothesis(
            hypothesis_id=f"hyp-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            hypothesis=hypothesis,
            confidence=confidence,
            alternatives=tuple(alternatives),
            discriminator=discriminator,
            evidence_refs=tuple(evidence_refs),
            timestamp=now_utc_iso(),
        )

    def experiment(
        self,
        task_id: str,
        *,
        actor: str,
        setup: dict,
        inputs_ref: str,
        result_ref: str,
        verified: bool = False,
    ) -> Experiment:
        self._check_actor(actor)
        return Experiment(
            experiment_id=f"exp-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            setup=dict(setup),
            inputs_ref=inputs_ref,
            result_ref=result_ref,
            verified=verified,
            timestamp=now_utc_iso(),
        )

    def diagnose(
        self,
        task_id: str,
        *,
        actor: str,
        diagnosis: str,
        confidence: str = "low",
        evidence_refs: tuple[str, ...],
        alternatives: tuple[str, ...],
    ) -> Diagnosis:
        self._check_actor(actor)
        return Diagnosis(
            diagnosis_id=f"diag-{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            actor=actor,
            diagnosis=diagnosis,
            confidence=confidence,
            evidence_refs=tuple(evidence_refs),
            alternatives=tuple(alternatives),
            timestamp=now_utc_iso(),
        )
