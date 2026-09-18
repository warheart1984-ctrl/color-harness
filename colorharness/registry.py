"""Team and agent registration with charter-validated capabilities."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from ._common import now_utc_iso

TEAM_CHARTER: dict[str, frozenset[str]] = {
    "coordinator": frozenset({"route", "transition", "record"}),
    "observer": frozenset(),
    "red": frozenset({"readonly_test"}),
    "blue": frozenset({"readonly_observe", "runbook_write"}),
    "black": frozenset({"readonly_diagnose"}),
    "purple": frozenset({"readonly_observe", "closure_validate"}),
    "gold": frozenset({"policy_write"}),
    "silver": frozenset({"branch_write", "config_write"}),
    "yellow": frozenset({"test", "lint", "policy_check", "smoke", "readiness_review"}),
    "green": frozenset({"release_plan", "rollback_exec"}),
    "white": frozenset({"ledger_write", "audit_write"}),
}

# Reviewer roles bound approvals and resolutions to *roles*, not team names.
# A role may be held by any registered agent (subject to team charter).
APPROVER_ROLES: frozenset[str] = frozenset(
    {"ci-operator", "security-lead", "platform-owner"}
)

# Roles allowed to perform resolution (UNBLOCK / DECISION_RESUME).
RESOLVER_ROLES: frozenset[str] = frozenset({"security-lead", "platform-owner"})

# Role -> teams that may hold it.
APPROVER_ROLE_TEAMS: dict[str, frozenset[str]] = {
    "ci-operator": frozenset({"yellow", "gold", "green", "coordinator", "white"}),
    "security-lead": frozenset({"white", "red", "black", "purple", "green", "coordinator"}),
    "platform-owner": frozenset({"coordinator", "white", "green"}),
}

# Risk tiers a given role is permitted to approve.
ROLE_RISK_TIERS: dict[str, frozenset[str]] = {
    "ci-operator": frozenset({"green", "yellow"}),
    "security-lead": frozenset({"green", "yellow", "orange", "red"}),
    "platform-owner": frozenset({"orange", "red"}),
}


class RegistrationError(Exception):
    pass


class UnknownTeamError(RegistrationError):
    pass


class DuplicateAgentError(RegistrationError):
    pass


class CapabilityNotAllowedError(RegistrationError):
    pass


class UnknownRoleError(RegistrationError):
    pass


class RoleNotAllowedError(RegistrationError):
    pass


@dataclass(frozen=True)
class AgentRegistration:
    agent_id: str
    team: str
    capabilities: tuple[str, ...]
    registered_at: str
    roles: frozenset[str] = frozenset()


class TeamRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentRegistration] = {}

    def register(
        self,
        agent_id: str,
        team: str,
        capabilities: tuple[str, ...] = (),
    ) -> AgentRegistration:
        team_norm = team.strip().lower()
        if team_norm not in TEAM_CHARTER:
            raise UnknownTeamError(team)
        existing = self._agents.get(agent_id)
        if existing is not None:
            raise DuplicateAgentError(
                f"agent_id '{agent_id}' already registered to team '{existing.team}'"
            )
        caps = tuple(capabilities)
        allowed = TEAM_CHARTER[team_norm]
        denied = set(caps) - set(allowed)
        if denied:
            raise CapabilityNotAllowedError(
                f"team '{team_norm}' does not allow capabilities: {sorted(denied)}"
            )
        reg = AgentRegistration(
            agent_id=agent_id,
            team=team_norm,
            capabilities=caps,
            registered_at=now_utc_iso(),
        )
        self._agents[agent_id] = reg
        return reg

    def unregister(self, agent_id: str) -> None:
        if agent_id not in self._agents:
            raise RegistrationError(f"agent '{agent_id}' is not registered")
        del self._agents[agent_id]

    def agent(self, agent_id: str) -> AgentRegistration:
        return self._agents[agent_id]

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._agents

    def team_of(self, agent_id: str) -> str:
        return self._agents[agent_id].team

    def agents_for(self, team: str) -> list[str]:
        team_norm = team.strip().lower()
        return sorted(aid for aid, reg in self._agents.items() if reg.team == team_norm)

    def all_agents(self) -> dict[str, AgentRegistration]:
        return dict(self._agents)

    # ------------------------------------------------------------------
    # Reviewer roles
    # ------------------------------------------------------------------

    def grant_role(self, agent_id: str, role: str) -> AgentRegistration:
        reg = self._agents.get(agent_id)
        if reg is None:
            raise RegistrationError(f"agent '{agent_id}' is not registered")
        if role not in APPROVER_ROLES:
            raise UnknownRoleError(f"unknown reviewer role '{role}'")
        allowed_teams = APPROVER_ROLE_TEAMS[role]
        if reg.team not in allowed_teams:
            raise RoleNotAllowedError(
                f"team '{reg.team}' may not hold role '{role}'"
            )
        new_reg = dataclasses.replace(
            reg, roles=reg.roles | frozenset({role})
        )
        self._agents[agent_id] = new_reg
        return new_reg

    def revoke_role(self, agent_id: str, role: str) -> AgentRegistration:
        reg = self._agents.get(agent_id)
        if reg is None:
            raise RegistrationError(f"agent '{agent_id}' is not registered")
        new_reg = dataclasses.replace(reg, roles=reg.roles - frozenset({role}))
        self._agents[agent_id] = new_reg
        return new_reg

    def role_of(self, agent_id: str) -> frozenset[str]:
        reg = self._agents.get(agent_id)
        return reg.roles if reg is not None else frozenset()

    def has_role(self, agent_id: str, role: str) -> bool:
        return role in self.role_of(agent_id)