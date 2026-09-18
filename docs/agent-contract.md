# Agent Contract — Color DevOps Agent Team

- RFC: RFC-0001-color-devops-agent-team
- Draft: 0.1
- Status: Under development (Phase 0)
- Canonical source of vocabulary and behavioral rules

> This file is the **single source of truth** for every term it defines and
> every behavioral rule it states. Other documents in this repository must
> refer to, not redefine, the vocabulary and rules below.

## 1. Purpose and scope

This contract binds every agent, team, and process in the Color DevOps Agent
Team system. It defines the vocabulary, the behavioral rules, the task
lifecycle, and the non-negotiables that keep the system auditable,
approval-gated, evidence-driven, and safe by default.

The system is **DevOps-only**. Its authority covers continuous integration,
continuous delivery, infrastructure-as-code, configuration, testing, security
scanning hooks, observability, and operational runbooks **within this
repository and its declared target environments**. No agent or team may
acquire authority over anything outside that scope.

The allowed domain set is the mechanical allowlist `DEVOPS_ALLOWLIST` in
`colorharness/scope.py` (`repo`, `ci_cd`, `iac`, `config`, `tooling`,
`tests`, `docs`, `monitoring`, `secrets_policy`). A task whose declared scope
names any other domain is refused at intake with `SCOPE_OUT_OF_BOUNDS`; a
scope cannot be expanded with an out-of-bounds domain either.

## 2. Canonical vocabulary

Each term below has exactly one definition. It is a contract violation for any
document to give a different meaning to a term defined here.

- **task** — A unit of DevOps work that enters the coordinator, receives a task
  ID, and is processed through the task state machine until it reaches an
  absorbing state (CLOSED, ROLLED_BACK, or an approved permanent BLOCKED).
  A task cannot change its declared scope without a new approval.

- **agent** — A single executing process or AI actor registered with the
  harness. Each agent has one `agent_id`, one lifecycle state at any time, and
  acts on behalf of exactly one team.

- **team** — A named group of agents sharing one mission, one scope, and one
  set of authorities. A team is a red, blue, black, purple, gold, silver,
  yellow, green, or white team. Teams do not overlap in authority.

- **evidence** — A verifiable, immutable fact that supports a claim or a state
  transition. Evidence is a record in the evidence ledger, has an `evidence_id`
  and a payload digest, and can be referenced but never edited.

- **approval** — A recorded, retractable decision by an authorized approver
  that permits a protected action to proceed. An approval has an approval
  record, an approver, a reviewer role, a scope, and an expiry. A missing,
  stale, or expired approval blocks execution.

- **reviewer role** — A named approval authority (`ci-operator`,
  `security-lead`, `platform-owner`) held by registered agents and distinct
  from team colors. Approvals are bound to roles, not to team names; a role
  only clears the risk tiers its authority covers, and approving with a
  revoked role voids the approval.

- **quorum** — The minimum set of valid approvals that clears a protected
  gate for a given risk tier: one `ci-operator` for Green/Yellow, one
  `security-lead` for Orange, and both a `security-lead` and a
  `platform-owner` from two distinct approvers for Red. A Red gate cannot be
  cleared by a single approver holding two roles.

- **risk** — The assessed operational consequence of an action before it is
  taken, classified as Green, Yellow, Orange, or Red. Risk classes the action;
  it does not name the executing team.

- **handoff** — The recorded transfer of a task from one team to the next
  team. A handoff must carry the task ID, the evidence references of the
  handing-off team, and the accepting team's acknowledgment.

- **block** — A deliberate, recorded refusal to let a task progress because a
  precondition, evidence requirement, approval, or check is unsatisfied.
  A block must name the blocking actor, the unsatisfied condition, and the
  evidence that demonstrates the condition remains unmet.

- **rollback** — The recorded reversal of a release or change to a known-good
  prior state, executed from a pre-existing rollback plan, and only by the
  team whose authority includes release execution.

- **completion** — The state in which a task has produced its required
  artifacts, evidence, and approvals, has been verified by an independent
  verifier, and has been recorded as CLOSED in the evidence ledger. A task is
  not complete if any evidence reference is missing, unverifiable, or marked
  incomplete.

- **scope** — The declared boundary of a task (resources, environments, and
  actions it may touch). Scope is declared at intake, recorded in the task
  record, and cannot be expanded without a new approval.

- **actor** — The agent, team, or component that performs an action or records
  a transition. Every transition and evidence record names its actor.

- **coordinator** — The routing and state-keeping component that assigns tasks
  to teams, validates every task state transition, and maintains the task
  registry and correlation record. The coordinator executes no task work
  itself.

- **observer** — The read-only role that collects factual state (repository
  state, CI results, service health, logs, metrics, dependency status, recent
  changes) and stores observations separately from interpretations. The observer
  holds no ledger handle and no storage path; persisting an observation as
  evidence is the white team's governed act (`record_observations`).

- **blue team** — Defense and operations: consumes factual observations and
  produces interpretations — threshold alerts, recommended actions, and runbook
  proposals — each of which must cite the evidence it is based on. Blue output
  is recorded as evidence (`alert`, `recommendation`, `runbook_entry`) by the
  white team so it stays attributable and auditable. Runbook proposals are
  never writes.

- **transition** — A recorded movement of a task between two task states (or an
  agent between two agent states). Every transition requires a trigger, an
  actor, a timestamp, a reason, and evidence references.

- **gate** — A checkpoint in the task lifecycle at which one or more checks must
  pass and, where the action is protected, an approval must be recorded before
  the task may move forward.

- **deployment** — The act of placing an artifact or configuration into a
  target environment (staging or production). Deployment is a protected action
  when the target is production.

- **production** — The environment that serves live end users or live
  third-party integrations. Actions touching production carry at least Orange
  risk and require recorded approval before execution.

- **destructive action** — An action that deletes, destroys, overwrites, or
  removes data, history, credentials, infrastructure, or irreversible state.
  Destructive actions carry Red risk and require recorded approval.

- **irreversible action** — An action that cannot be undone and has no rollback
  plan. Irreversible actions are never executed without recorded approval, and
  are declined when they fall outside the approving authority's scope.

- **blast radius** — The set of environments, services, users, and data that
  can be affected if an action fails. An action with material blast radius or
  difficult rollback carries at least Orange risk.

- **read-only** — An operation that collects, inspects, or derives state and may
  not create, modify, or delete any durable system or record. The observer role
  and Red Team baseline are read-only.

- **correlation ID** — The shared identifier that ties one logical incident,
  task tree, or change to all of its events, evidence, approvals, and spans
  across teams. Task IDs are one-to-one with correlation IDs.

- **task ID** — The unique identifier of a single task, assigned by the
  coordinator at intake, stable for the lifetime of the task.

- **decision record** — An immutable record of a decision (approve, reject,
  block, escalate, roll back, pause) containing the decider, the reasoning, the
  evidence references used, and the decision's effective scope and expiry.

- **evidence reference** — An identifier or link that points to a specific
  evidence record or ledger entry. A transition or claim is only as strong as
  its evidence references.

- **escalation** — The recorded movement of a task from its current team to a
  higher authority because the team cannot satisfy a precondition or the task
  requires a decision above its authority. Escalation pauses normal progression
  until a decision is recorded.

- **quarantine** — An agent-level protective state (defined by the ATHP harness)
  that suspends an agent from task execution when a policy, heartbeat, or
  sandbox condition fails. A quarantined agent is restored to IDLE only through
  a recorded recovery decision.

- **change manifest** — The document listing every file, branch, resource, and
  configuration an implementation touches, together with its diff summary and
  its task ID and approval scope. A change with no manifest is not attributable.

- **exception** — A recorded, time-boxed waiver from a standard that must name
  the standard overridden, the requested duration, the approving authority, and
  an expiry date. Exceptions without an expiry are invalid.

- **runbook** — A documented, step-by-step operational procedure (defensive,
  diagnostic, recovery, or release) that any qualified operator can follow.

- **rollback plan** — A written plan, produced before release execution, that
  names the trigger conditions, the rollback steps, the rollback owner, and the
  verification that a rollback succeeded. A release without a rollback plan is
  not approvable.

- **release** — The approval-gated act of delivering a verified artifact to a
  production environment under a monitored rollout and a rollback plan.

- **staging** — A non-production environment that mirrors production closely
  enough to validate deployment behavior. Changes to staging carry Yellow risk.

- **verification** — The independent execution of tests, checks, and policy
  validations that produce evidence about whether a change is deployment-ready.
  Verification is never performed by the team that produced the change.

- **diagnosis** — An evidence-based explanation of an incident, failed build,
  regression, or drift that states its supporting evidence, its uncertainty,
  and its plausible alternatives. A diagnosis without uncertainty is a claim,
  not a diagnosis.

- **hypothesis** — A testable candidate explanation under investigation, with
  a stated confidence level and at least one controlled experiment or
  discriminator that could refute it.

- **confidence** — The measured or assessed likelihood that a diagnosis,
  hypothesis, or remediation is correct, expressed as a level (Low, Medium,
  High) with the evidence used to derive it.

- **finding** — A reproducible observation from authorized adversarial testing
  that includes reproduction steps, impact, severity, and a remediation
  recommendation. A finding with no reproduction is not a finding.

- **reproduction** — The recorded steps and output that demonstrate a finding or
  failure repeatably and independently.

- **remediation** — A concrete, evidenced change or control that addresses a
  finding, verified by independent re-testing before closure.

- **monitoring** — The ongoing, read-only observation of a released change's
  health metrics and logs against defined thresholds, continued until a success
  or rollback decision is recorded.

- **idempotency** — The property that repeating a command or message with the
  same identifier does not duplicate its effect or its recorded transition.
  A restarted command must not duplicate a completed transition.

- **idempotency fingerprint** — The sha256 (JCS) of an operation's payload
  fields bound to an `(actor, request_id)` key. Replaying the same key with
  the same fingerprint returns the stored outcome; reusing the key with a
  different fingerprint is an `IDEMPOTENCY_CONFLICT` and is refused.

- **manifest digest** — The sha256 over the JCS body of the whole ledger's
  record list (`manifest_digest` in `EvidenceLedger.manifest()`). It is the
  external anchor: persisted elsewhere, it proves the ledger was, or was not,
  altered since the anchor was taken.

- **evidence ledger** — The append-only store of all evidence records. Ledger
  entries are immutable; at-most-once supersession is recorded as new entries.

- **audit** — The white-team-kept, immutable record of scope declarations,
  approvals, decisions, timelines, evidence references, action items, and task
  completion that supports post-incident and post-release review.

## 3. Behavioral contract

The following clauses bind all agents and teams. They are non-negotiable.

### 3.1 General clauses

- G1. Every protected action requires a recorded, in-scope, non-expired
  approval before execution. Protected actions are those carrying Orange or Red
  risk (see `docs/authority-matrix.md`).
- G2. **No agent may silently broaden a task.** Expanding scope, moving from
  diagnosis to implementation, or moving from staging to production requires a
  new recorded approval.
- G3. Every transition records its actor, timestamp, reason, and evidence
  references. No transition occurs without these four attributes.
- G4. Read-only roles stay read-only. The observer and a baseline Red Team
  posture never create, modify, or delete durable state.
- G5. No team approves its own work. Verification, release approval, and
  closure must involve a different authority than the team that produced the
  change.
- G6. An evidence record marked incomplete cannot be marked complete. Completing
  a record requires adding the missing mandatory fields in a new, complete
  record; the incomplete record remains in the ledger.
- G7. Secrets are never written to logs, evidence, change manifests, or audit
  output. Secrets exist only in approved secret stores.
- G8. A block is always evidence-backed. An agent that blocks a task must cite
  the unsatisfied condition and the evidence showing it is unsatisfied.
- G9. A restarted command must not duplicate a completed state transition
  (idempotency). Replayed messages return their stored outcome.
- G10. Pause outranks progress. Any team member may request a pause; the white
  team may pause work whenever evidence or authority is insufficient.
- G11. Approvals are bound to reviewer roles, never to team colors. An
  approval must be recorded by a role with authority over the task's risk tier
  (see the quorum in `docs/authority-matrix.md` §4); an approval whose
  approver no longer holds the recorded role is void. Approval default expiry
  is 90 days.
- G12. Out-of-scope domains are refused, not ignored. A task whose declared
  scope names a domain outside `DEVOPS_ALLOWLIST` is rejected at intake, and a
  scope expansion may not introduce one.
- G13. Secret material is scanned for at intake, on transitions, and before
  any ledger append. Secrets (Stripe/AWS/GitHub token forms, private key
  headers) are refused with `SECRET_EXPOSURE`; the ledger never stores them.
- G14. The watchdog quarantines agents that miss their heartbeat threshold and
  escalates tasks held in BLOCKED/ESCALATED past the stale-block window;
  a quarantined agent's transitions are refused with `AGENT_QUARANTINED`.

### 3.2 Team obligations

- Red Team: tests failure modes only within explicitly authorized boundaries,
  refuses unspecified targets and destructive tests, and every finding includes
  reproduction, impact, severity, and remediation recommendation.
- Blue Team: maintains monitoring, alerts, runbooks, and defensive
  recommendations; every recommendation cites evidence.
- Black Team: investigates opaque failures with hypotheses, confidence levels,
  alternative-cause tracking, and controlled experiments; never deploys or
  mutates production directly; never claims certainty beyond its evidence.
- Purple Team: maps findings to controls, tests, alerts, and runbooks, and
  demonstrates (by re-test evidence) that a remediation actually closes the
  finding.
- Gold Team: owns versioned standards, reference pipelines, policy-as-code, and
  reliability direction; exceptions require documented approval and expiry.
- Silver Team: prepares changes in isolated branches or worktrees with a change
  manifest and rollback metadata; does not merge and does not deploy.
- Yellow Team: independently runs tests, lint, policy checks, security scanning,
  smoke tests, and readiness review; rejects changes that fail; cannot approve
  its own implementation.
- Green Team: prepares deployment plans, coordinates approved releases, watches
  rollout health, and executes rollback procedures; production execution remains
  approval-gated and requires a rollback plan before execution.
- White Team: maintains scope, evidence, approvals, timelines, decision
  records, incident reports, and audit trails, and may pause work when evidence
  or authority is insufficient.
- Coordinator: routes tasks, validates every transition, and enforces the task
  state machine; executes no task work itself.

## 4. Task lifecycle state machine

The coordinator drives every task through this deterministic state machine.
These are **task states**, distinct from ATHP **agent states**
(INIT, IDLE, EXECUTING, QUARANTINED, ESCALATED, SHUTDOWN, REJECTED).

```
INTAKE -> OBSERVE -> DIAGNOSE -> PLAN -> BUILD -> VERIFY -> APPROVE
   -> RELEASE -> MONITOR -> CLOSE

Intercepted/stalled states:
   BLOCKED        (reachable from any state; cleared by a recorded unblock)
   ESCALATED      (reachable from any state; resolved by a recorded decision)
   ROLLED_BACK    (reachable from RELEASE/MONITOR via a rollback plan)
```

- A transition requires a legal (current state, trigger) pair, an actor, a
  timestamp, a reason, and evidence references.
- Trigger names are frozen; the implementation (`colorharness._common`) is the
  canonical table:

| From | Trigger | To |
| --- | --- | --- |
| INTAKE | ROUTE | OBSERVE |
| OBSERVE | OBSERVATIONS_READY | DIAGNOSE |
| DIAGNOSE | DIAGNOSIS_ACCEPTED | PLAN |
| PLAN | PLAN_APPROVED | BUILD |
| BUILD | IMPLEMENTATION_READY | VERIFY |
| VERIFY | VERIFICATION_PASSED | APPROVE |
| APPROVE | RELEASE_APPROVED | RELEASE |
| RELEASE | DEPLOYED | MONITOR |
| MONITOR | SUCCESS_CONFIRMED | CLOSED |
| RELEASE, MONITOR | ROLLBACK_INITIATED | ROLLED_BACK |
| any non-absorbing (not already holding) | BLOCK | BLOCKED (resume recorded) |
| any non-absorbing (not already escalated) | ESCALATE | ESCALATED (resume recorded) |
| BLOCKED | UNBLOCK | recorded resume state |
| ESCALATED | DECISION_RESUME | recorded resume state |
- Illegitimate transitions are rejected with a recorded STATE_INVALID result.
- ABSORBING states: CLOSED, ROLLED_BACK, and a permanently BLOCKED task that
  has an approved blocking decision.
- The coordinator re-applies the state machine on restart; already-completed
  transitions are replayed, never re-executed.

## 5. Approval and risk gates

- Risk is classified at intake and re-assessed before every protected action.
  Risk may move only toward higher risk without restarting review.
- Approval gates appear at BUILD (Yellow), APPROVE (Green + coordinator), and
  RELEASE (explicit production approval). See `docs/authority-matrix.md` for
  the full matrix.
- A gate closes only when its checks pass and its approvals meet the quorum
  for the task's current risk tier. Approvals default to a 90-day expiry;
  expired, revoked, or role-voided approvals never count toward a quorum.
- A task's approval token is an approval specified by the role-based quorum;
  approvals are recorded per role and per approver, so a Red gate needs two
  distinct approvers (a security-lead and a platform-owner).
- Replaying a transition that already succeeded returns the stored outcome
  (idempotency); reusing an idempotency key with different payload content is
  refused as an `IDEMPOTENCY_CONFLICT`.

## 6. Contract non-negotiables

1. Production and destructive actions are approval-gated, always.
2. No authority exists outside the DevOps scope.
3. Evidence is immutable; incomplete evidence cannot become complete.
4. Blocking and escalation are always evidence-backed.
5. No team self-approves; no agent broadens scope silently; no restarted
   command duplicates a completed transition.

## 7. Acceptance (Phase 0)

- Every term above has exactly one definition, mechanically enforced by
  `tests/test_phase0_documentation.py`.
- No team has authority outside the DevOps scope defined in
  `docs/authority-matrix.md`.
- Production and destructive actions are approval-gated in this contract
  (clause G1, §5) and in `docs/authority-matrix.md`.

## 8. Acceptance (Phase 0b — hardening)

Mechanically enforced by `tests/test_phase0b_hardening.py`:

- Out-of-scope domains are refused, not ignored (G12).
- Secret material is detected and refused at intake, on transitions, and on
  ledger append (G13).
- Approvals are role-bound and tier-quorum-satisfying, with a 90-day default
  expiry (G11).
- Replayed messages return stored outcomes; conflicting payloads under an
  existing key are refused (idempotency fingerprint).
- The watchdog quarantines silent agents and escalates stale blocks (G14).
- The ledger exposes a manifest digest that detects any change since the
  anchor was taken.