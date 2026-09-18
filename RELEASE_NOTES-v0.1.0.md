# Color Harness v0.1.0

Initial release of the governed Color DevOps Agent Team.

## Included

- Coordinator task state machine with validated transitions.
- White Team governance, approvals, evidence ledger, audit output, and
  append-only manifest verification.
- Observer and Blue Team read-only operations.
- Black Team evidence-based diagnosis.
- Silver Team isolated change manifests with rollback metadata.
- Yellow Team independent verification gates.
- Red Team authorized adversarial findings.
- Purple Team remediation closure validation.
- Gold Team versioned standards, reference pipelines, and expiring exceptions.
- Green Team approval-gated release plans and rollback operations.
- Watchdog quarantine and stale-block escalation.
- Idempotent transition replay and secret-exposure protections.

## Validation

The release includes 177 passing tests, including eight Phase 10 scenarios:

1. all nine teams registered;
2. failed CI blocks verification progression;
3. dependency vulnerability finding;
4. staged release with rollback readiness;
5. watchdog quarantine and recovery;
6. idempotent transition replay;
7. unauthorized release rejection;
8. complete release/rollback evidence recording.

## Install

```powershell
pip install color-harness
```

## ATHP relationship

ATHP remains a separate agent transport and lifecycle package. It consumes
Color Harness as an external dependency; the repositories are not vendored
into one another.

