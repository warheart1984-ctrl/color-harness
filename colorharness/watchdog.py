"""Watchdog: heartbeat liveness, agent quarantine, and stale-block escalation."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable, Optional

from .governance import GovernanceError, WhiteTeam
from .registry import TeamRegistry

SYSTEM_AGENT = "watchdog.sys-1"
HEARTBEAT_MISSES_THRESHOLD = 3
HEARTBEAT_INTERVAL_SECONDS = 60
DEFAULT_STALE_BLOCK_SECONDS = 600  # BLOCKED/ESCALATED held for 10 minutes


def _iso_to_epoch(value: str) -> float:
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt.timestamp()


class Watchdog:
    """Tracks per-agent heartbeats, quarantines silent agents, and escalates
    tasks that sit in BLOCKED/ESCALATED beyond the stale-block threshold."""

    def __init__(
        self,
        *,
        stale_block_seconds: int = DEFAULT_STALE_BLOCK_SECONDS,
        now_fn: Optional[Callable[[], float]] = None,
        registry: Optional[TeamRegistry] = None,
        governance: Optional[WhiteTeam] = None,
    ) -> None:
        self.stale_block_seconds = stale_block_seconds
        self._now = now_fn or time.time
        self._heartbeats: dict[str, float] = {}
        self._quarantined: set[str] = set()
        self.registry: Optional[TeamRegistry] = None
        self.governance: Optional[WhiteTeam] = None
        self._state_loaded = False
        if registry is not None or governance is not None:
            if registry is None or governance is None:
                raise ValueError("Watchdog requires both registry and governance")
            self.bind(registry=registry, governance=governance)

    def bind(self, *, registry: TeamRegistry, governance: WhiteTeam) -> None:
        """Bind durable authorization and restore quarantine state from White's ledger."""
        if governance.registry is not registry:
            raise GovernanceError("Watchdog and WhiteTeam must share the same registry")
        if governance.ledger.path is None:
            raise GovernanceError("Watchdog requires a persistent White ledger")
        self.registry = registry
        self.governance = governance
        self._quarantined.clear()
        for record in governance.ledger.records:
            if record.record_type != "decision":
                continue
            payload = record.payload or {}
            agent_id = (payload.get("scope") or {}).get("agent_id")
            if not agent_id:
                continue
            if payload.get("decision_type") == "watchdog_quarantine":
                self._quarantined.add(agent_id)
            elif payload.get("decision_type") == "watchdog_unquarantine":
                self._quarantined.discard(agent_id)
        self._state_loaded = True

    # ------------------------------------------------------------------
    # Heartbeats
    # ------------------------------------------------------------------

    def heartbeat(
        self, agent_id: str, *, actor: str, now: Optional[float] = None
    ) -> None:
        self._require_bound()
        if actor != agent_id or not self.registry.is_registered(agent_id):
            raise GovernanceError("heartbeat must be submitted by its registered agent")
        self._heartbeats[agent_id] = now if now is not None else self._now()

    def last_heartbeat(self, agent_id: str) -> Optional[float]:
        return self._heartbeats.get(agent_id)

    def missed_heartbeats(
        self,
        agent_id: str,
        *,
        interval_seconds: int = HEARTBEAT_INTERVAL_SECONDS,
        now: Optional[float] = None,
    ) -> int:
        last = self._heartbeats.get(agent_id)
        if last is None:
            return HEARTBEAT_MISSES_THRESHOLD + 1
        at = now if now is not None else self._now()
        elapsed = at - last
        if elapsed <= interval_seconds:
            return 0
        return max(0, int((elapsed - 1) // interval_seconds))

    def is_stale(
        self,
        agent_id: str,
        *,
        interval_seconds: int = HEARTBEAT_INTERVAL_SECONDS,
        threshold: int = HEARTBEAT_MISSES_THRESHOLD,
        now: Optional[float] = None,
    ) -> bool:
        return self.missed_heartbeats(
            agent_id, interval_seconds=interval_seconds, now=now
        ) >= threshold

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------

    def quarantine(self, agent_id: str, *, actor: str, reason: str = "") -> None:
        self._require_bound()
        if self.registry.team_of(actor) != "white":
            raise GovernanceError("only a registered White actor may quarantine manually")
        if agent_id in self._quarantined:
            return
        self._record_state_change("watchdog_quarantine", agent_id, actor, reason)
        self._quarantined.add(agent_id)

    def _quarantine_stale(self, agent_id: str) -> None:
        # A never-seen agent has no liveness history yet; only a previously
        # observed heartbeat can age into an automatic quarantine.
        if self.last_heartbeat(agent_id) is None or not self.is_stale(agent_id):
            return
        self._require_bound()
        if agent_id not in self._quarantined:
            self._record_state_change(
                "watchdog_quarantine", agent_id, SYSTEM_AGENT, "missed heartbeats"
            )
            self._quarantined.add(agent_id)

    def is_quarantined(self, agent_id: str) -> bool:
        self._require_bound()
        self._quarantine_stale(agent_id)
        return agent_id in self._quarantined

    def unquarantine(
        self, agent_id: str, *, actor: str, reason: str = "recovery approved"
    ) -> None:
        self._require_bound()
        team = self.registry.team_of(actor)
        if team not in {"white", "coordinator"}:
            raise GovernanceError("only White or coordinator actors may unquarantine")
        if agent_id not in self._quarantined:
            return
        self._record_state_change("watchdog_unquarantine", agent_id, actor, reason)
        self._quarantined.discard(agent_id)

    def _require_bound(self) -> None:
        if not self._state_loaded or self.registry is None or self.governance is None:
            raise GovernanceError("Watchdog authorization and durable state are not loaded")

    def _record_state_change(
        self, decision_type: str, agent_id: str, actor: str, reason: str
    ) -> None:
        self._require_bound()
        team = self.registry.team_of(actor)
        self.governance.ledger.append(
            "decision",
            actor=actor,
            team=team,
            source="watchdog://quarantine",
            payload={
                "decision_type": decision_type,
                "decider": actor,
                "reasoning": reason,
                "scope": {"agent_id": agent_id},
            },
        )

    @property
    def quarantined(self) -> frozenset[str]:
        self._require_bound()
        return frozenset(self._quarantined)

    # ------------------------------------------------------------------
    # Stale-block escalation
    # ------------------------------------------------------------------

    def escalate_stale_blocks(
        self,
        governance,
        task_states: dict[str, str],
        *,
        now: Optional[float] = None,
    ) -> list[str]:
        """Escalate any task held in BLOCKED/ESCALATED past the threshold.

        ``task_states`` maps task_id -> ISO timestamp for when the task entered
        its current state. Returns the escalated task ids.
        """
        at = now if now is not None else self._now()
        escalated: list[str] = []
        for task_id, entered_iso in task_states.items():
            try:
                entered_epoch = _iso_to_epoch(entered_iso)
            except (ValueError, TypeError):
                continue
            if at - entered_epoch <= self.stale_block_seconds:
                continue
            if not governance.is_paused(task_id):
                governance.escalate(
                    task_id,
                    actor=SYSTEM_AGENT,
                    reason=f"held in state beyond {self.stale_block_seconds}s",
                )
                escalated.append(task_id)
        return escalated
