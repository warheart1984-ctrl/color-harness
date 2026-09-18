# Authority Matrix — Color DevOps Agent Team

- Canonical vocabulary: see `docs/agent-contract.md`
- Evidence/approval records: see `docs/evidence-schema.md`
- RFC under development: `RFC-0001-color-devops-agent-team.md`

## 1. Scope boundary

This system is **DevOps-only**. In-scope domains (each team's authority is
limited to these):

`CI/CD pipelines`, `repository tooling`, `infrastructure-as-code`, `staging and
production deployment automation`, `configuration`, `tests`, `security
scanning hooks`, `observability (logs/metrics/alerts)`, `runbooks`, `dependency
management`, and `operational documentation within this repository`.

A team's "Out of scope" cell below lists domains that team **never** touches.
No team has authority over application feature logic, business decisions,
external services beyond the declared target environments, credentials that it
was not granted, or any activity the coordinator has not routed to it.

Scope expansion requires a new recorded approval (contract clause G2). The
mechanical allowlist is `DEVOPS_ALLOWLIST` in `colorharness/scope.py`; any
domain outside it is refused at intake and on expansion
(`SCOPE_OUT_OF_BOUNDS`).

## 2. Operational risk color model

| Color | Meaning | Examples | Requires approval? |
| --- | --- | --- | --- |
| Green | Read-only or reversible local work | collecting metrics, reading logs, local analysis, drafting docs | No (recorded by White) |
| Yellow | Changes to code, CI, staging, or non-production infrastructure | commit to feature branch, staging deploy, config change in staging | No for authored change; Yes at release gate |
| Orange | Material blast radius or difficult rollback | staging rollout to shared infra, large migration, config affecting many services | Yes (before execution) |
| Red | Production, credentials, deletion, security controls, irreversible actions | production release, secret rotation, delete environment, policy change | Yes (explicit, before execution) |

Risk color and team color are separate concepts (a Red Team test can be
low-risk when isolated; a Green Team release can be high-risk). Risk is
assigned before execution and may only move toward higher risk without
restarting review.

## 3. Team authorities (caps)

| Team | In scope | Out of scope | Cannot | Approval in scope? |
| --- | --- | --- | --- | --- |
| Coordinator | route tasks, validate state transitions, keep task/registry/correlation records | doing task work itself | execute any task | N/A (records all approvals) |
| Red | authorized adversarial tests of CI/CD, deployments, reliability, security controls in authorized environments | unspecified targets, destructive tests, production real-world impact | run outside authorized boundaries; test without a task ID | Yes, test boundaries are approved scope |
| Blue | monitoring, alerts, runbooks, defense, hardening recommendations | mutating production controls without approval | change policies outside approval | recommendations cite evidence |
| Black | deep diagnostics, hypotheses, confidence, controlled experiments, incident timeline | deploying or mutating production directly | deploy or mutate production directly; claim certainty beyond evidence | diagnosis must be evidence-backed |
| Purple | read-only observation; mapping findings to controls/tests/alerts/runbooks; closure validation | authoring the changes it validates | declare closure without re-test evidence | closure requires re-test evidence |
| Gold | versioned standards, reference pipelines, policy-as-code, reliability direction | making exceptions it does not approve | grant unbounded exceptions | exceptions expire |
| Silver | isolated branches/worktrees, change manifests, diff summaries, rollback metadata | merging, deploying | merge or deploy | every change attributable to task + approval scope |
| Yellow | independent tests, lint, policy checks, security scanning, smoke tests, readiness review | approving its own implementation | approve its own work | independent of implementation team |
| Green | deployment plans, approved releases, rollout health, rollback | executing releases without approval | run production without approval or rollback plan | production requires explicit approval |
| White | scope declarations, evidence ledger, approvals, timelines, decision records, audit | executing task work | mark incomplete evidence complete | may pause when evidence/authority insufficient |

## 4. Protected actions and gates

Protected actions carry Orange or Red risk and **always require a recorded
approval before execution**. The "Approval required" column names the form of
approval; the "Gate" column names where the check is enforced.

| Action | Team | Risk color | Approval required | Gate |
| --- | --- | --- | --- | --- |
| production release | Green | Red | explicit approval (coordinator + green) + verified rollback plan | APPROVE / RELEASE |
| rollback execution | Green | Red | pre-approved by the release approval + rollback plan | MONITOR / ROLLED_BACK |
| destructive delete of environment or data | Silver/Green | Red | explicit destructive-action approval | BUILD / APPROVE |
| credential rotation or injection | Green | Red | explicit approval, secret-store only, secrets never logged | APPROVE / RELEASE |
| security-control or policy change | Gold/Yellow | Red | explicit approval + yellow verification | VERIFY / APPROVE |
| staging rollout with material blast radius | Green | Orange | recorded approval | APPROVE |
| production config drift correction | Blue | Orange | recorded approval | APPROVE |
| scope expansion of a task | Coordinator | Orange | new approval for the expanded scope | any state |
| escalated decision | White/Coordinator | varies | recorded decision resolves ESCALATED | ESCALATED |
| merging an implementation branch | Yellow/Green | Yellow | independent verification required | VERIFY |

Rules:

- **No self-approval.** Yellow cannot approve its own implementation; the
  verifier of a change is never the author of that change.
- **Pause.** White may pause work at any point when evidence or authority is
  insufficient. Pause outranks progress (contract clause G10).
- **Block.** Any team may block with evidence; a blocked task cannot advance
  until the block is cleared by a recorded unblock decision.
- **Escalation.** A task that needs authority above its current team moves to
  ESCALATED and pauses normal progression until a decision is recorded.
- **Expiry.** Every approval has an expiry. Expired approvals must be renewed;
  renewing re-runs the approval record, never mutates the old one.
- **Roles over team colors.** Approvals are recorded by reviewer role
  (`ci-operator`, `security-lead`, `platform-owner`), not by team color. An
  approval whose approver no longer holds the recorded role is void and never
  counts toward a gate.

### Approval roles and quorum

An approval is valid only if the approver holds the recorded reviewer role and
that role has authority over the task's **current** risk tier. An approval
clears a protected gate only when the tier's quorum is met.

| Risk tier | Required role(s) | Quorum | Example approvers |
| --- | --- | --- | --- |
| Green | `ci-operator` | 1 approval | `ci-operator` on a read-only task |
| Yellow | `ci-operator` | 1 approval | CI operator approving a staging change |
| Orange | `security-lead` | 1 approval | security lead approving blast-radius-limited rollout |
| Red | `security-lead` + `platform-owner` | 2 distinct approvers | security lead + platform owner on production release |

Rules:

- One approver holding two roles does **not** clear a Red gate (two distinct
  approvers are required).
- Approvals default to a 90-day expiry (`APPROVAL_TTL_SECONDS`).
- A role grant can be revoked; revoking the role voids every pending approval
  recorded under it.
- Resolution of BLOCKED/ESCALATED (`UNBLOCK`, `DECISION_RESUME`) requires the
  coordinator system agent or an agent holding a resolver role
  (`security-lead`, `platform-owner`); other actors are refused with
  `AUTH_INVALID`.

## 5. Escalation paths

- Team → Coordinator: routing, transition, or blocking conflicts.
- Coordinator → White: authority, scope, or evidence-sufficiency questions.
- Any team → White: request to pause (evidence/authority insufficient).
- Watchdog: escalates tasks held in BLOCKED/ESCALATED beyond the stale-block
  window (10 minutes by default) and quarantines agents that miss the
  heartbeat threshold (3 misses by default).
- White/Coordinator → designated human platform owner: production, credentials,
  deletion, or irreversible actions — a human approval is required for Red-risk
  execution.

## 6. Audit requirement

All approvals, blocks, escalations, rollback plans, and releases are recorded
as decision records in the evidence ledger (see `docs/evidence-schema.md`) and
reported by White Team.