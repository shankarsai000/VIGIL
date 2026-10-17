"""Static AST Verification Test for Tool Decision Boundary (CLAUDE.md Rule A & Phase V1).

INVARIANT:
Only ArmorIQ may decide whether an agent's tool call is allowed or blocked.
No function outside backend/app/policies/armoriq_gate.py may return an 'allowed' or
'denied' authorization verdict for an agent tool call.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_no_client_side_tool_authorization_functions():
    """Scans all Python files in backend/app/ to ensure no client-side tool pre-check functions exist."""
    app_dir = REPO_ROOT / "backend" / "app"
    gate_file = app_dir / "policies" / "armoriq_gate.py"

    violations = []

    for py_file in app_dir.rglob("*.py"):
        if py_file.resolve() == gate_file.resolve():
            continue  # The gate is the single authorized enforcement path

        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"), filename=str(py_file))
        except Exception as e:
            continue

        for node in ast.walk(tree):
            # 1. Prohibit functions named evaluate_sink_policy or similar client pre-checks
            if isinstance(node, ast.FunctionDef):
                if node.name in ["evaluate_sink_policy", "authorize_tool_call", "check_tool_permitted"]:
                    violations.append((str(py_file.relative_to(REPO_ROOT)), node.lineno, f"Forbidden tool-authorization function: '{node.name}'"))

            # 2. Check for return dicts with {'allowed': False/True} specifically for tool execution
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
                keys = [k.value for k in node.value.keys if isinstance(k, ast.Constant)]
                if "allowed" in keys and ("tool_name" in keys or "taint_level" in keys or "tool" in keys):
                    violations.append((str(py_file.relative_to(REPO_ROOT)), node.lineno, "Forbidden client-side tool decision dictionary"))

    assert len(violations) == 0, f"Found client-side tool decision violations: {violations}"
