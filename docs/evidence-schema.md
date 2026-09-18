# Evidence Schema — Color DevOps Agent Team

- Canonical vocabulary: see `docs/agent-contract.md`
- Authority and gates: see `docs/authority-matrix.md`

This document defines the evidence record schema, the append-only evidence
ledger, and the integrity rules that make every transition, approval, block,
diagnosis, and release auditable.

## 1. Guiding rules

1. Evidence is immutable. A record in the ledger can be **referenced and
   superseded**, never edited.
2. A record marked incomplete cannot be marked complete. Completing a record
   appends a new record that carries all mandatory fields and references the
   incomplete record it supersedes.
3. Every task state transition records at least one evidence reference.
4. Secrets never appear in evidence payloads, details, or sources. A record
   that would carry a secret carries a reference to the secret store instead.
5. The ledger is tamper-evident: each record stores the digest of the previous
   record, forming a hash chain.

## 2. Evidence record (JSON)

| Field | Type | Max length | Required | Notes |
| --- | --- | --- | --- | --- |
| `evidence_id` | string | 64 | yes | unique id, created once, never reused |
| `event_id` | string | 64 | yes | message/event that produced this record |
| `type` | enum | 32 | yes | one of the types in §3 |
| `status` | enum | 16 | yes | `draft`, `verified`, or `complete` |
| `actor` | string | 64 | yes | agent/team/component that produced it |
| `agent_id` | string | 64 | no | registering ATHP agent, when applicable |
| `team` | string | 32 | yes | color team (or `coordinator`) |
| `task_id` | string | 64 | no | owning task when applicable |
| `correlation_id` | string | 64 | no | ties incident/change tree together |
| `timestamp` | string | 32 | yes | UTC ISO-8601 with milliseconds, `Z` suffix |
| `source` | string | 256 | yes | file/URI/command the evidence came from |
| `payload_digest` | string | 64 | yes | sha256 of `payload` (JCS) |
| `prev_hash` | string | 64 | yes | sha256 of the previous ledger record |
| `payload` | object | — | yes | schema-bound detail, see §4 |
| `refs` | string[] | — | no | evidence references (parents, superseded entries) |
| `signature` | string | 128 | no | harness/signer HMAC when signing is enabled |
| `retention_days` | int | — | yes | retention window (min 90 by default) |

`payload_digest` and `prev_hash` make records content-addressable and
tamper-evident. A record whose `prev_hash` does not match the actual previous
record is evidence of tampering (or a fork) and disqualifies the rest.

## 3. Record types

| Type | Used by | Payload (§4) |
| --- | --- | --- |
| `transition` | coordinator | current state, new state, trigger, reason code |
| `observation` | observer / blue | collected fact (logs, metrics, CI result, health, dependencies) |
| `hypothesis` | black | hypothesis text, confidence, alternatives, discriminator |
| `experiment` | black | controlled experiment, inputs, result |
| `diagnosis` | black | diagnosis, confidence, evidence references, alternatives |
| `test_result` | yellow | command, version, exit status, artifact location |
| `finding` | red | reproduction steps, impact, severity, remediation recommendation |
| `remediation` | purple | change/control applied, re-test evidence, closure verdict |
| `approval` | white/coordinator | approver, scope, expiry, gated action |
| `decision` | white/coordinator | decision type, decider, reasoning, effective scope |
| `block` | any team | blocking actor, unsatisfied condition, evidence |
| `unblock` | coordinator | clearing decision, evidence |
| `handoff` | coordinator | from team, to team, task id, evidence handed over |
| `rollback_plan` | green | trigger conditions, steps, owner, verification |
| `release` | green | released artifact, target, plan reference, approval reference |
| `rollback` | green | executed rollback, plan reference, result |
| `scope_declaration` | white | declared scope, allowed domains, boundary |
| `exception` | white/gold | overridden standard, duration, expiry, approver |

## 4. Payload schemas (mandatory sub-details)

Completeness requires the mandatory fields of the record (§2) **and** the
mandatory sub-details of the payload type:

- `transition`: `previous_state`, `new_state`, `trigger`, `reason_code`,
  `actor`, `timestamp`, and ≥1 evidence reference.
  (These map one-to-one onto the ATHP `EvidenceSpan` fields so harness evidence
  logs can be imported directly.)
- `observation`: `observation_type` (logs|metrics|health|ci|dependency|
  repo_state|changes), `detail`, `interpretation` **must be null or absent** —
  facts and interpretations are stored separately.
- `hypothesis`: `hypothesis`, `confidence` (Low|Medium|High),
  `alternatives[]`, `discriminator`.
- `experiment`: `setup`, `inputs_ref`, `result_ref`, `verified` (bool).
- `diagnosis`: `diagnosis`, `confidence`, `evidence_refs[]`, `alternatives[]`.
- `test_result`: `command`, `version`, `exit_status`, `artifacts_ref`,
  `evidence_location`.
- `finding`: `reproduction[]`, `impact`, `severity`,
  `remediation_recommendation`.
- `remediation`: `change_ref`, `re_test_ref`, `verdict` (closed|open).
- `approval`: `approver`, `scope`, `expiry`, `gated_action`, `decision_id`.
- `decision`: `decision_type`, `decider`, `reasoning`, `scope`, `expiry`.
- `block`: `reason_code`, `condition`, `evidence_refs[]`.
- `release`: `artifact_ref`, `target_environment`, `plan_ref`,
  `approval_refs[]`.

## 5. Completeness rule

An evidence record is **complete** only when every required field (§2) and
every mandatory payload sub-detail (§4) is present and non-empty. Incomplete
records are stored as `draft` or `verified` and cannot be marked `complete`
in place. To complete a record, append a new complete record that references
the old one in `refs` (supersession). Sequence of a record's life:

```
draft --verify--> verified --verify+marshal--> complete
       (superseding records append; never in-place mutation)
```

## 6. Interop with the ATHP harness (RFC-0042)

The harness already records transition evidence (`EvidenceSpan`, fields
`previous_state`, `new_state`, `trigger`, `decision_id`, `message_id`,
`actor`, `timestamp`, `reason_code`) in an in-memory `evidence_log` and to
`evidence.jsonl` when persistence is enabled. These spans are imported as
`transition` records in the ledger, with `task_id`/`correlation_id` attached by
the coordinator. A harness span and its ledger record share the same
`decision_id`; the ledger record's `refs` include the span's `message_id`.

## 7. Example record

```json
{
  "evidence_id": "evt-01HZX9K8QPFM1T2Y3X",
  "event_id": "msg-01HZX9K8QP-A",
  "type": "transition",
  "status": "complete",
  "actor": "coordinator",
  "agent_id": "team.silver.build-7",
  "team": "coordinator",
  "task_id": "task-01HZX9K6",
  "correlation_id": "corr-01HZX9K6",
  "timestamp": "2026-09-18T14:15:41.000Z",
  "source": "lifecycle://transition/apply",
  "payload_digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "prev_hash": "a3bf4f1b2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015",
  "payload": {
    "previous_state": "PLAN",
    "new_state": "BUILD",
    "trigger": "PLAN_APPROVED",
    "reason_code": "NONE"
  },
  "refs": ["msg-01HZX9K8QP-A"],
  "signature": "",
  "retention_days": 90
}
```