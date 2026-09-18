"""DevOps scope allowlist: everything outside is REJECT."""

from __future__ import annotations

# Explicit allowlist of domains the system may touch. Every other domain is
# out of scope; a task that names an out-of-bounds domain is refused at intake.
DEVOPS_ALLOWLIST: frozenset[str] = frozenset(
    {
        "repo",          # source repository state, branches, history metadata
        "ci_cd",         # CI/CD pipelines and runners
        "iac",           # infrastructure-as-code and deployment automation
        "config",        # configuration management and application config
        "tooling",       # build/dev tooling, package managers
        "tests",         # test suites, fixtures, test infrastructure
        "docs",          # operational documentation and runbooks
        "monitoring",    # observability, metrics, logs, dashboards
        "secrets_policy",  # secrets-handling policy and secret references
    }
)

# Non-domain keys that may appear as *details* inside a declared domain scope
# (e.g. which environments, resources, or services a CI/CD task may touch).
DETAIL_KEYS: frozenset[str] = frozenset(
    {"environments", "resources", "services", "targets", "commands"}
)


class ScopeOutOfBoundsError(Exception):
    pass


def out_of_bounds_keys(scope: dict) -> list[str]:
    """Return the scope keys that are not on the DevOps allowlist."""
    bad = [
        key
        for key in scope
        if key not in DEVOPS_ALLOWLIST and key not in DETAIL_KEYS
    ]
    return sorted(set(bad))


def validate_scope(scope: dict) -> None:
    """Reject any scope that names a domain outside the DevOps allowlist."""
    bad = out_of_bounds_keys(scope)
    if bad:
        raise ScopeOutOfBoundsError(
            f"scope names non-DevOps domains: {bad}; "
            f"allowlist: {sorted(DEVOPS_ALLOWLIST)}"
        )