"""Color DevOps Agent Team — core coordinator, task state machine,
team/agent registry, and structured event log (Phase 1).

The package depends only on the Python standard library. It records every
task transition as an immutable, durable event; a restarted coordinator
replays the event log and never duplicates a completed transition.
"""

from .registry import (
    CapabilityNotAllowedError,
    DuplicateAgentError,
    RegistrationError,
    TeamRegistry,
    UnknownTeamError,
)
from .coordinator import Coordinator
from .risk import RiskClass
from .ledger import (
    EvidenceLedger,
    EvidenceRecord,
    IncompleteEvidenceError,
    LedgerError,
    LedgerImmutableError,
)
from .governance import (
    ApprovalRecord,
    GovernanceError,
    NoSelfApprovalError,
    RiskRegressionError,
    ScopeApprovalRequired,
    ScopeDeclaration,
    ScopeNotDeclaredError,
    WhiteTeam,
    scope_covers,
)

__all__ = [
    "Coordinator",
    "TeamRegistry",
    "RegistrationError",
    "UnknownTeamError",
    "DuplicateAgentError",
    "CapabilityNotAllowedError",
    "RiskClass",
    "EvidenceLedger",
    "EvidenceRecord",
    "LedgerError",
    "IncompleteEvidenceError",
    "LedgerImmutableError",
    "WhiteTeam",
    "ApprovalRecord",
    "ScopeDeclaration",
    "GovernanceError",
    "NoSelfApprovalError",
    "RiskRegressionError",
    "ScopeApprovalRequired",
    "ScopeNotDeclaredError",
    "scope_covers",
]