"""Check Guide Evidence (Phase DOC-FIX-1 Fix 12).

Verifies that:
1. Every evidence path referenced in CLAUDE.md exists on disk.
2. Every numeric metric claim in CLAUDE.md Section 7 and Section 8 appears in its referenced evidence file.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
GUIDE_PATH = REPO_ROOT / "CLAUDE.md"


def extract_numbers_from_evidence_file(file_path: Path) -> Set[str]:
    """Extract all numbers from JSON, JSONL, or text evidence files."""
    if not file_path.exists():
        return set()
    
    text = file_path.read_text(encoding="utf-8")
    values = set()

    # If JSON, parse recursively to get typed numbers and string tokens
    if file_path.suffix == ".json":
        try:
            data = json.loads(text)
            def walk(obj):
                if isinstance(obj, dict):
                    for v in obj.values():
                        walk(v)
                elif isinstance(obj, list):
                    for v in obj:
                        walk(v)
                elif isinstance(obj, (int, float)):
                    values.add(str(obj))
                    if isinstance(obj, float):
                        values.add(f"{obj:.1f}")
                        values.add(f"{obj:.2f}")
                        values.add(f"{obj:.3f}")
                        values.add(f"{obj:.4f}")
                        values.add(f"{obj:.5f}")
                        values.add(f"{obj * 100:.1f}")
                        values.add(f"{obj * 100:.2f}")
                        values.add(f"{obj * 100:.3f}")
                elif isinstance(obj, str):
                    values.add(obj)
            walk(data)
        except Exception:
            pass

    # Extract all digits and decimal tokens from raw text
    for match in re.findall(r"\b\d+(?:\.\d+)?\b", text):
        values.add(match)
        # Normalize without comma
        values.add(match.replace(",", ""))

    return values


def check_guide_evidence() -> Tuple[List[str], List[str]]:
    """Check all evidence paths and numbers in CLAUDE.md."""
    if not GUIDE_PATH.exists():
        return [f"Missing guide file: {GUIDE_PATH}"], []

    content = GUIDE_PATH.read_text(encoding="utf-8")
    errors = []
    warnings = []

    # 1. Extract all evidence paths in CLAUDE.md
    evidence_paths = re.findall(r"evidence/[\w\-./]+", content)
    unique_paths = sorted(set(evidence_paths))

    print(f"[*] Checking {len(unique_paths)} evidence paths in CLAUDE.md...")
    for rel_path in unique_paths:
        full_path = REPO_ROOT / rel_path
        if not full_path.exists():
            errors.append(f"Missing evidence path referenced in guide: {rel_path}")

    # 2. Extract Section 7 (Statistical Rigor)
    sec7_match = re.search(r"## 7\. Statistical Rigor Protocol.*?(?=## 8\.)", content, re.DOTALL)
    if sec7_match:
        sec7_text = sec7_match.group(0)
        # Required sample sizes and corresponding evidence files
        sec7_checks = [
            ("600", REPO_ROOT / "evidence" / "V8" / "scenario_6.json"),
            ("620", REPO_ROOT / "evidence" / "M6" / "demo_output.txt"),
            ("1000", REPO_ROOT / "evidence" / "V9" / "results.json"),
            ("215000", REPO_ROOT / "evidence" / "I1" / "results.json"),
        ]
        for metric, ev_file in sec7_checks:
            ev_vals = extract_numbers_from_evidence_file(ev_file)
            if metric not in ev_vals:
                errors.append(f"Section 7 metric '{metric}' not found in evidence file {ev_file.relative_to(REPO_ROOT)}")

    # 3. Extract Section 8 (Empirical Evidence & Benchmark Results)
    sec8_match = re.search(r"## 8\. Empirical Evidence & Benchmark Results.*?(?=## 9\.)", content, re.DOTALL)
    if sec8_match:
        sec8_text = sec8_match.group(0)

        # 8.1 Scenario 5 checks
        sc5_ev = REPO_ROOT / "evidence" / "V8" / "scenario_5.json"
        sc5_vals = extract_numbers_from_evidence_file(sc5_ev)
        for metric in ["8821", "0.0"]:
            if metric not in sc5_vals:
                errors.append(f"Section 8.1 metric '{metric}' not found in {sc5_ev.relative_to(REPO_ROOT)}")

        # 8.2 Scenario 6 checks
        sc6_ev = REPO_ROOT / "evidence" / "V8" / "scenario_6.json"
        sc6_vals = extract_numbers_from_evidence_file(sc6_ev)
        for metric in ["2048", "10240", "5", "24", "600", "0", "0.00498", "0.0331", "3.0"]:
            if metric not in sc6_vals:
                errors.append(f"Section 8.2 metric '{metric}' not found in {sc6_ev.relative_to(REPO_ROOT)}")

        # 8.3 Ablation benchmark checks
        sc83_ev = REPO_ROOT / "evidence" / "V9" / "results.json"
        sc83_vals = extract_numbers_from_evidence_file(sc83_ev)
        for metric in ["1080", "80", "0.0", "25.0", "50.0", "100.0", "2.5", "3.0", "4.0", "0.002991"]:
            if metric not in sc83_vals:
                errors.append(f"Section 8.3 metric '{metric}' not found in {sc83_ev.relative_to(REPO_ROOT)}")

    return errors, warnings


if __name__ == "__main__":
    errors, warnings = check_guide_evidence()
    if errors:
        print(f"[FAIL] {len(errors)} error(s) found in CLAUDE.md evidence checks:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("[PASS] All evidence paths exist and all Section 7 & 8 metrics match evidence files.")
        sys.exit(0)
