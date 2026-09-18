"""Watchdog: heartbeat liveness, agent quarantine, and stale-block escalation."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable, Optional

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
    ) -> None:
        self.stale_block_seconds = stale_block_seconds
        self._now = now_fn or time.time
        self._heartbeats: dict[str, float] = {}
        self._quarantined: set[str] = set()

    # ------------------------------------------------------------------
    # Heartbeats
    # ------------------------------------------------------------------

    def heartbeat(self, agent_id: str, *, now: Optional[float] = None) -> None:
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

    def quarantine(self, agent_id: str, *, reason: str = "") -> None:
        self._quarantined.add(agent_id)

    def is_quarantined(self, agent_id: str) -> bool:
        return agent_id in self._quarantined

    def unquarantine(self, agent_id: str) -> None:
        self._quarantined.discard(agent_id)

    @property
    def quarantined(self) -> frozenset[str]:
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