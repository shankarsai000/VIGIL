"""Static AST Test for Single Threshold Table Enforcement (Rule H & Phase DOC-FIX-1).

INVARIANT:
All score thresholds, containment bands, and gate trigger numbers must live in config/thresholds.yaml.
No code outside config/ and tests/ may hardcode the literal values:
0.45, 0.65, 0.75, 0.85, 0.90, or 0.92.
"""

from __future__ import annotations

import ast
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROHIBITED_VALUES = {0.45, 0.65, 0.75, 0.85, 0.90, 0.92}
PROHIBITED_STRINGS = {"0.45", "0.65", "0.75", "0.85", "0.90", "0.92"}


def test_no_hardcoded_threshold_literals_outside_config_and_tests():
    """Scans all Python files across the codebase to ensure no prohibited threshold literals exist."""
    violations = []

    for py_file in REPO_ROOT.rglob("*.py"):
        rel_path = str(py_file.relative_to(REPO_ROOT)).replace("\\", "/")

        # Exclude directories where thresholds/tests naturally reside or tooling environments
        if (
            rel_path.startswith("config/")
            or "tests/" in rel_path
            or rel_path.startswith(".venv/")
            or rel_path.startswith("scratch/")
            or rel_path.startswith("archive/")
            or rel_path.startswith("build/")
            or rel_path.startswith("dist/")
        ):
            continue

        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"), filename=str(py_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            # Check ast.Constant (Python 3.8+)
            if isinstance(node, ast.Constant):
                if isinstance(node.value, float):
                    for prohibited in PROHIBITED_VALUES:
                        if abs(node.value - prohibited) < 1e-6:
                            violations.append((rel_path, node.lineno, node.value))

    assert len(violations) == 0, f"Found hardcoded threshold literals outside config/ and tests/: {violations}"
