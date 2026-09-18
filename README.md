# Color DevOps Agent Team

A DevOps-only multi-agent coordination system made of nine color teams, a
Coordinator, and a read-only Observer. It is **auditable, approval-gated,
evidence-driven, and safe by default**, and it builds on the ATHP harness
(RFC-0042) for agent registration, signed envelopes, lifecycle state machines,
quarantine, and evidence spans.

## The teams

| Team | Mission |
| --- | --- |
| Coordinator | Routes work, validates every task state transition, keeps task and correlation records. Executes no task work itself. |
| Red | Adversarial failure testing in authorized environments; reproducible findings, never vague criticism. |
| Blue | Defense and operations: monitoring, alerts, runbooks, hardening. |
| Black | Deep diagnostics of opaque, severe, or cross-system failures; hypotheses with confidence and alternatives; never deploys or mutates production directly. |
| Purple | Read-only observation of state; maps findings to controls/tests/alerts/runbooks and proves closure. |
| Gold | Versioned platform patterns, reliability standards, reference pipelines, policy-as-code. |
| Silver | Isolated change preparation (branches/worktrees, change manifests, rollback metadata). Never merges or deploys. |
| Yellow | Independent verification: tests, lint, policy, security scanning, smoke tests, readiness review. Cannot approve its own work. |
| Green | Approved releases: deployment plans, rollout health, rollback procedures. Production remains approval-gated. |
| White | Governance and record: scope, evidence, approvals, timelines, decision records, incident reports, audit trails. May pause work. |

Backbone rule: **no agent may silently broaden a task** — scope expansion,
moving from diagnosis to implementation, or from staging to production requires
a new recorded approval.

## Color and risk model

Risk labels (the color everything is classified with before execution):

| Color | Meaning |
| --- | --- |
| Green | read-only or reversible local work |
| Yellow | changes to code, CI, staging, or non-production infrastructure |
| Orange | material blast radius or difficult rollback |
| Red | production, credentials, deletion, security controls, or irreversible actions |

Team color and operational risk are separate: a Red Team test may be low-risk
when isolated; a Green Team release may be high-risk when production-impacting.
Every task carries both a responsible team and a risk level.

## Task lifecycle

```
INTAKE -> OBSERVE -> DIAGNOSE -> PLAN -> BUILD -> VERIFY -> APPROVE
   -> RELEASE -> MONITOR -> CLOSE

BLOCKED  (clearable; evidence-backed)
ESCALATED  (paused until a decision)
ROLLED_BACK  (via a pre-existing rollback plan)
```

Every transition records actor, timestamp, reason, and evidence references;
illegal transitions are rejected; a restarted command never duplicates a
completed transition.

## Build status

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | Repository and contract setup | done |
| 0b | Hardening: scope allowlist, secret scanning, reviewer roles + quorum, idempotency fingerprints, watchdog, ledger manifest | done |
| 1 | Core coordinator and state machine | done |
| 2 | White Team governance layer | done |
| 3 | Observer and Blue Team | done |
| 4 | Black Team diagnostics | done |
| 5 | Silver Team implementation | done |
| 6 | Yellow Team verification | done |
| 7 | Red and Purple Teams | done |
| 8 | Gold Team standards and architecture | planned |
| 9 | Green Team release operations | planned |
| 10 | Integration and adversarial validation | planned |

## Repository layout

```
README.md
RFC-0001-color-devops-agent-team.md
docs/
  agent-contract.md      canonical vocabulary + behavioral contract
  evidence-schema.md     evidence record + append-only ledger + manifest
  authority-matrix.md    scope, caps, risk colors, approval gates, quorum
tests/
  test_phase0_documentation.py
  test_phase0b_hardening.py
  test_phase1_coordinator.py
  test_phase2_governance.py
  test_phase3_observer_blue.py
  test_phase4_black_team.py
  test_phase5_silver_team.py
  test_phase6_yellow_team.py
  test_phase7_red_purple.py
colorharness/            color-team coordinator + task state machine (Phase 1)
                         + White Team governance: scope, risk, approvals,
                         evidence ledger, audit (Phase 2)
                         + hardening: scope allowlist, secret scanner,
                         reviewer roles/quorum, watchdog, ledger manifest
                         + Observer (read-only facts) + Blue Team (monitoring,
                         alerts, recommendations, runbooks) (Phase 3)
                         + Black Team (hypotheses, experiments, evidence-based
                         diagnoses) + coordinator evidence gates (Phase 4)
                         + Silver Team (change manifests with rollback
                         metadata; no merge/deploy) (Phase 5)
                         + Yellow Team (independent checks; failures block
                         VERIFICATION_PASSED) (Phase 6)
                         + Red Team (authorized adversarial testing; findings
                         require targets and reproduction; destructive refused
                         without approval) + Purple Team (closure validation;
                         closure requires re-test evidence) (Phase 7)
athp/                    RFC-0042 harness (moon_base, server, lifecycle, conformance)
```

## Running the checks

Requires Python 3.12 and pytest.

```
python -m pytest tests/ -v
```

## Guarantees

- Production and destructive actions are approval-gated, always.
- No team has authority outside DevOps scope; out-of-scope domains are refused
  at intake and on scope expansion.
- Approvals are bound to reviewer roles and satisfy a risk-tier quorum (Red
  requires a security-lead and a platform-owner from two distinct approvers);
  approvals expire after 90 days by default.
- Secrets are scanned for and refused at intake, on transitions, and at every
  ledger append.
- Evidence is immutable; incomplete evidence cannot be marked complete.
- Blocking and escalation are evidence-backed; the watchdog quarantines silent
  agents and escalates stale blocks.
- No team self-approves; no agent broadens scope silently; no restarted
  command duplicates a completed transition, and reusing an idempotency key
  with different payload content is refused.