"""Operational risk classification for the Color DevOps Agent Team."""

from __future__ import annotations

from enum import Enum


class RiskClass(str, Enum):
    GREEN = "green"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED = "red"


_ORDER = {
    RiskClass.GREEN: 0,
    RiskClass.YELLOW: 1,
    RiskClass.ORANGE: 2,
    RiskClass.RED: 3,
}

PROTECTED: frozenset[RiskClass] = frozenset({RiskClass.ORANGE, RiskClass.RED})

ACTION_RISK: dict[str, RiskClass] = {
    "release": RiskClass.RED,
    "production_release": RiskClass.RED,
    "rollback": RiskClass.RED,
    "destructive_delete": RiskClass.RED,
    "credential_rotation": RiskClass.RED,
    "security_control_change": RiskClass.RED,
    "scope_expansion": RiskClass.ORANGE,
    "staging_deploy": RiskClass.ORANGE,
    "production_config_drift": RiskClass.ORANGE,
    "ci_change": RiskClass.YELLOW,
    "staging_change": RiskClass.YELLOW,
    "branch_write": RiskClass.YELLOW,
    "config_write": RiskClass.YELLOW,
    "observe": RiskClass.GREEN,
    "read": RiskClass.GREEN,
}


def normalize(risk: RiskClass | str) -> RiskClass:
    if isinstance(risk, RiskClass):
        return risk
    return RiskClass(str(risk).strip().lower())


def classify_action(action: str) -> RiskClass:
    return ACTION_RISK.get(action.strip().lower(), RiskClass.YELLOW)


def rank(risk: RiskClass) -> int:
    return _ORDER[risk]


def is_higher(a: RiskClass, b: RiskClass) -> bool:
    return rank(a) > rank(b)


def is_protected(risk: RiskClass) -> bool:
    return risk in PROTECTED


def max_risk(*risks: RiskClass) -> RiskClass:
    return max(risks, key=rank)