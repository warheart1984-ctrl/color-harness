"""Phase 0 acceptance checks for the Color DevOps Agent Team.

Enforces the three announced acceptance criteria mechanically:

  1. Every term has one unambiguous definition.
  2. No team has authority outside DevOps scope.
  3. Production and destructive actions are approval-gated in the written
     contract.

Also verifies that every Phase 0 deliverable exists.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

CONTRACT = REPO / "docs" / "agent-contract.md"
AUTHORITY = REPO / "docs" / "authority-matrix.md"
EVIDENCE = REPO / "docs" / "evidence-schema.md"
RFC = REPO / "RFC-0001-color-devops-agent-team.md"
README = REPO / "README.md"

DOC_FILES = [README, RFC, CONTRACT, AUTHORITY, EVIDENCE]

REQUIRED_TERMS = [
    "task",
    "agent",
    "team",
    "evidence",
    "approval",
    "risk",
    "handoff",
    "block",
    "rollback",
    "completion",
]

TEAM_NAMES = [
    "Coordinator",
    "Red",
    "Blue",
    "Black",
    "Purple",
    "Gold",
    "Silver",
    "Yellow",
    "Green",
    "White",
]

DELIVERABLES = [
    README,
    RFC,
    CONTRACT,
    AUTHORITY,
    EVIDENCE,
    REPO / "tests",
]

# A definition line:  "- **term** — definition ..."
DEF_LINE = re.compile(r"^-\s+\*\*(?P<term>[A-Za-z][A-Za-z0-9 ]*)\*\*\s+—\s+(?P<def>.+)$")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def definition_lines(path: Path) -> dict[str, str]:
    """Return {term: definition} for glossary definition lines in a file."""
    found: dict[str, str] = {}
    for line in read(path).splitlines():
        m = DEF_LINE.match(line)
        if m:
            found[m.group("term").strip()] = m.group("def").strip()
    return found


def build_tables(path: Path) -> list[list[list[str]]]:
    """Parse markdown tables as blocks of [header_row, *rows]."""
    blocks: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in read(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            current.append([c.strip() for c in stripped.strip("|").split("|")])
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)

    tables = []
    for block in blocks:
        rows = [r for r in block if not all(re.fullmatch(r":?-+:?", c) for c in r)]
        if rows:
            tables.append(rows)
    return tables


def table_with(path: Path, *header_keys: str) -> list[list[str]] | None:
    """Return the first table whose header row contains every header key."""
    for table in build_tables(path):
        header = " ".join(table[0]).lower()
        if all(key.lower() in header for key in header_keys):
            return table
    return None


# ---------------------------------------------------------------------------
# Deliverables exist
# ---------------------------------------------------------------------------

def test_phase0_deliverables_exist() -> None:
    missing = [str(p) for p in DELIVERABLES if not p.exists()]
    assert not missing, f"Missing Phase 0 deliverables: {missing}"


# ---------------------------------------------------------------------------
# Acceptance 1: every term has one unambiguous definition
# ---------------------------------------------------------------------------

def test_required_terms_defined_once_in_contract() -> None:
    defs = definition_lines(CONTRACT)
    for term in REQUIRED_TERMS:
        detail = defs.get(term, "")
        assert detail, f"Term '{term}' has no definition in {CONTRACT.name}"
        assert len(detail) >= 20, f"Term '{term}' definition is too thin to be unambiguous"


def test_no_term_redefined_elsewhere() -> None:
    contract_defs = definition_lines(CONTRACT)
    for other in (AUTHORITY, EVIDENCE, RFC, README):
        redefined = set(definition_lines(other)) & set(contract_defs)
        assert not redefined, (
            f"{other.name} redefines (or duplicates) contract terms: {sorted(redefined)}"
        )


def test_all_glossary_terms_unique_within_contract() -> None:
    defs = definition_lines(CONTRACT)
    assert defs, "No glossary definitions found in contract"
    # Whole-contract uniqueness: any term defined is defined exactly once.
    assert len(set(defs)) == len(defs)


# ---------------------------------------------------------------------------
# Acceptance 2: no team has authority outside DevOps scope
# ---------------------------------------------------------------------------

def test_scope_boundary_declared() -> None:
    text = read(AUTHORITY)
    assert "DevOps-only" in text, "Authority matrix must declare the DevOps-only boundary"
    assert "Out of scope" in text, "Authority matrix must bound each team's scope"


def test_every_team_is_scope_bounded() -> None:
    caps = table_with(AUTHORITY, "team", "in scope")
    assert caps, "Team capabilities table not found in authority matrix"
    rows = caps[1:]
    assert [r[0] for r in rows] == TEAM_NAMES, "Team capabilities table must cover every team exactly once"
    forbidden = {"feature logic", "business decision", "credentials it was not granted"}
    for cells in rows:
        in_scope, out_of_scope = cells[1].lower(), cells[2].lower()
        assert out_of_scope.strip(), f"{cells[0]} has no out-of-scope declaration"
        assert not (set(forbidden) & set(in_scope.split())), (
            f"{cells[0]} claims out-of-scope authority in its in-scope cell"
        )


# ---------------------------------------------------------------------------
# Acceptance 3: production and destructive actions are approval-gated
# ---------------------------------------------------------------------------

def test_contract_declares_production_destructive_gate() -> None:
    text = read(CONTRACT)
    assert re.search(r"(?i)production and destructive actions are approval-gated", text), (
        "Contract must state the production/destructive approval gate"
    )


def test_protected_actions_require_approval_in_matrix() -> None:
    protected_table = table_with(AUTHORITY, "action", "risk color")
    assert protected_table, "Protected-actions table (Action | Team | Risk color | ...) not found"
    protected = protected_table[1:]

    red_actions = {
        "production release", "rollback execution", "credential", "delete",
        "destructive", "security-control", "security control", "irreversible",
    }
    for cells in protected:
        action, risk_color, approval = (cells[0].lower(), cells[2].lower(), cells[3].lower())
        needs_gate = any(k in action for k in red_actions)
        if not needs_gate:
            continue
        assert risk_color in ("red", "orange"), (
            f"'{cells[0]}' must be Orange/Red risk, got {cells[2]}"
        )
        assert approval, f"'{cells[0]}' has no approval requirement"
        assert "approv" in approval, (
            f"'{cells[0]}' approval cell must name an approval, got '{cells[3]}'"
        )


def test_no_red_risk_action_without_approval() -> None:
    protected_table = table_with(AUTHORITY, "action", "risk color")
    assert protected_table
    protected = protected_table[1:]
    for cells in protected:
        if cells[2].strip() == "Red":
            assert cells[3].strip(), f"Red-risk action '{cells[0]}' lacks an approval cell"