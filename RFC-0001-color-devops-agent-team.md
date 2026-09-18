# RFC-0001 — Color DevOps Agent Team

- Status: Draft 0.1
- Date: 2026-09-18
- Supersedes: none
- Related: RFC-0042 ATHP (Agents Test Harness Protocol) — underlying harness
- Canonical terms: `docs/agent-contract.md`
- Authority: `docs/authority-matrix.md`
- Evidence: `docs/evidence-schema.md`

## 1. Summary

This RFC proposes a DevOps-only, multi-agent coordination system made of nine
color teams (Red, Blue, Black, Purple, Gold, Silver, Yellow, Green, White)
plus a Coordinator and a read-only Observer. The system is auditable,
approval-gated, evidence-driven, and safe by default. It builds on the ATHP
harness (RFC-0042) for agent registration, signed envelopes, lifecycle state
machine, quarantine, and evidence spans.

The core discipline: **every task is routed through a deterministic state
machine; every transition, approval, block, and decision is an immutable
evidence record; production and destructive actions are never executed without
a recorded approval; no agent silently broadens a task.**

## 2. Motivation and scope

Orchestrating many autonomous agents for CI/CD, incident response, and release
management fails when teams overlap in authority, act on unsupported claims,
or mutate state outside their scope. This RFC fixes the operating model so that
each failure mode is caught by a control:

| Failure mode | Control |
| --- | --- |
| Silently broadened task | scope declaration + new-approval rule (G2) |
| Unsupported certainty | Black Team confidence + alternatives, no out-of-level claims |
| Self-approval | required independence of verifier from author |
| Production or destructive action without approval | protected-action gate (Orange/Red) |
| Replayed or restarted work | idempotency: replayed messages/machines return stored outcome |
| Lost handoffs | recorded handoff with acknowledgment, coordinator tracking |

Scope: DevOps within this repository and its declared target environments
(see authority matrix). Out of scope: application feature logic, business
decisions, and any authority outside DevOps.

## 3. Operating model

### 3.1 Teams

| Team | Mission | Constraint |
| --- | --- | --- |
| Coordinator | Route work, validate task state transitions, keep task and correlation records | Executes no task work itself |
| Observer | Read-only collection of repository state, CI results, health, logs, metrics, dependencies, changes | No write capability |
| Red | Adversarial failure testing in authorized environments; reproducible findings | Refuses unspecified targets/destructive tests |
| Blue | Defense: monitoring, alerts, runbooks, hardening | Recommendations cite evidence |
| Black | Deep diagnostics of opaque failures (hypotheses, confidence, alternatives, controlled experiments) | Cannot deploy or mutate production directly |
| Purple | Maps findings to controls/tests/alerts/runbooks; proves closure | Closure requires re-test evidence |
| Gold | Platform patterns, reliability standards, reference pipelines, policy-as-code | Recommendations versioned; exceptions expire |
| Silver | Isolated implementation: branches/worktrees, change manifests, rollback metadata | Cannot merge or deploy |
| Yellow | Independent verification: tests, lint, policy/security, smoke, readiness | Cannot approve its own work; failed checks block |
| Green | Approved releases: plans, rollout health, rollback | Production action approval-gated; rollback plan before execution |
| White | Governance: scope, evidence, approvals, timelines, decisions, audit; pause power | Cannot mark incomplete evidence complete |

### 3.2 Color model (risk labels)

- **Green** — read-only or reversible local work.
- **Yellow** — changes to code, CI, staging, or non-production infrastructure.
- **Orange** — material blast radius or difficult rollback.
- **Red** — production, credentials, deletion, security controls, or
  irreversible actions.

Risk color is assigned before execution and may only move toward higher risk
without restarting review.

### 3.3 Risk model

Team color and operational risk are independent. A Red Team test may be
low-risk when isolated; a Green Team release may be high-risk when
production-impacting. Every task therefore carries both a responsible team and
a risk level. Protected actions (Orange/Red) require recorded approval.

## 4. Task lifecycle

```
INTAKE -> OBSERVE -> DIAGNOSE -> PLAN -> BUILD -> VERIFY -> APPROVE
   -> RELEASE -> MONITOR -> CLOSE
```

Supporting states: `BLOCKED`, `ESCALATED`, `ROLLED_BACK`.

- Every transition records actor, timestamp, reason, evidence references.
- Illegal transitions are rejected (STATE_INVALID) and recorded.
- Restarting a command does not duplicate a completed transition.

## 5. Governance rules

1. G1 — Protected actions require recorded, in-scope, non-expired approval.
2. G2 — No agent may silently broaden a task; scope expansion needs new approval.
3. G3 — Every transition records actor, timestamp, reason, evidence references.
4. G4 — Read-only roles never write durable state.
5. G5 — No team approves its own work.
6. G6 — Incomplete evidence cannot be marked complete.
7. G7 — Secrets never appear in logs, evidence, or audit output.
8. G8 — Blocks are evidence-backed.
9. G9 — Replayed/restarted commands never duplicate completed transitions.
10. G10 — Pause outranks progress (White may pause when evidence/authority is insufficient).

## 6. Acceptance criteria (per build phase)

| Phase | Deliverable | Acceptance |
| --- | --- | --- |
| 0 Repository & contract | README, RFC-0001, docs/*, tests/ | unique definitions; DevOps-only authority; production/destructive approval-gated |
| 1 Coordinator & state machine | task model, registration, transitions, task/correlation IDs, event log | illegal transitions rejected; complete transition records; no duplicate on restart |
| 2 White governance | scope, authority matrix, approvals, risk, evidence ledger, pause, audit output | missing approval blocks; scope expansion needs approval; incomplete cannot complete |
| 3 Observer & Blue | read-only collection; monitoring/alerts/runbooks | observer has no write; facts/interpretations separated; recommendations cite evidence |
| 4 Black diagnostics | hypotheses, confidence, alternatives, experiments, timeline | diagnosis states evidence+uncertainty; no unsupported certainty |
| 5 Silver implementation | branch isolation, change manifest, diff summary, secret policy, rollback metadata | cannot merge/deploy; attributable; secrets never logged |
| 6 Yellow verification | test runner, lint/policy, security hooks, smoke, readiness | no self-approval; failed checks block; results include command/version/status/evidence location |
| 7 Red & Purple | authorized adversarial testing; closure validation | Red refuses unspecified/destructive; findings complete; Purple proves closure |
| 8 Gold standards | versioned standards, policy-as-code, reference pipelines | recommendations versioned; standards testable; exceptions approved+expiry |
| 9 Green release | staged delivery, rollout monitoring, rollback, reporting | production needs explicit approval; rollback plan pre-release; monitoring confirms success or triggers rollback/escalation |
| 10 Integration | run all scenarios to completion with evidence, no bypass | every scenario produces complete evidence; no protected action bypasses approval |

## 7. Required scenarios (Phase 10)

1. Failed CI build.
2. Dependency vulnerability.
3. Staging deployment failure.
4. Production rollback simulation.
5. Unauthorized destructive request.
6. Red Team finding closed by Purple Team.
7. Agent timeout or lost handoff.
8. Duplicate command replay.

The system is ready for pilot use only when all scenarios produce complete
evidence and no protected action bypasses approval.

## 8. Relationship to ATHP (RFC-0042)

ATHP provides the wire protocol (signed envelopes, clock skew, version
negotiation), the agent lifecycle (INIT/IDLE/EXECUTING/QUARANTINED/ESCALATED/
SHUTDOWN/REJECTED), quarantines, idempotent replay, sandbox policy, and
transition evidence spans. The color system adds the **task-level** state
machine, team routing, governance, approvals, and the evidence ledger that
imports ATHP spans as transition records.

## 9. Open questions and risks

- Who holds human approval authority for Red-risk execution in pilot? (Assumed:
  the repository owner.)
- Whether Green rollback execution requires a second human approval beyond the
  release approval. (Draft rule: the release approval pre-authorizes its own
  rollback plan.)
- Quarantine of a team's agents during an incident must not stall the evidence
  ledger (ledger writes are coordinator-owned).
- Time-boxing for BLOCKED/ESCALATED to force periodic re-review.

## 10. Decision log

| Date | Decision | Decision record |
| --- | --- | --- |
| 2026-09-18 | Adopt task state machine + evidence-ledger model on ATHP harness | pending (Phase 2) |