"""Verification script for Phase M6 Acceptance Criteria.

Checks:
1. The demo runs end to end offline in under two minutes.
2. Every file path cited in docs/POLICY_IMMUNE.md, docs/DEMO_SCRIPT.md, and ENHANCEMENTS.md exists.
3. The privacy tests pass.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent


def check_paths_cited_in_doc(doc_path: Path) -> dict:
    text = doc_path.read_text(encoding="utf-8")
    # Matches markdown links [text](path) or [`text`](path) or code blocks `path`
    # Filter for repo paths starting with backend/, config/, docs/, evidence/, scripts/, demo/
    link_pattern = re.compile(r'\[([^\]]+)\]\((file:///[^)]+|[^)]+)\)')
    code_pattern = re.compile(r'`([a-zA-Z0-9_\-\./\\]+\.[a-zA-Z0-9]+)`')

    cited_paths = set()

    for match in link_pattern.finditer(text):
        target = match.group(2)
        target = target.replace("file:///", "").replace("file://", "")
        # Normalize windows drive prefix if present (d:/vigil-v2/vigil-v2/...)
        if "vigil-v2" in target:
            idx = target.find("vigil-v2")
            # find relative part after repository root
            parts = Path(target).parts
            # Look for subpath relative to repo
            rel = None
            for i, p in enumerate(parts):
                if p.lower() in ("backend", "config", "docs", "evidence", "scripts", "demo", "frontend"):
                    rel = Path(*parts[i:])
                    break
            if rel:
                cited_paths.add(str(rel).split("#")[0].split(":")[0])
        elif any(target.startswith(prefix) for prefix in ("backend/", "config/", "docs/", "evidence/", "scripts/", "demo/", "frontend/")):
            cited_paths.add(target.split("#")[0].split(":")[0])

    for match in code_pattern.finditer(text):
        candidate = match.group(1).replace("\\", "/")
        if any(candidate.startswith(prefix) for prefix in ("backend/", "config/", "docs/", "evidence/", "scripts/", "demo/", "frontend/")):
            cited_paths.add(candidate.split("#")[0].split(":")[0])

    results = {}
    for p_str in sorted(cited_paths):
        p_clean = p_str.strip().rstrip(".").rstrip(",")
        p = repo_root / p_clean
        results[p_clean] = p.exists()

    return results


def main():
    print("[1/3] Running demo end-to-end offline...")
    t0 = time.time()
    res = subprocess.run(
        [sys.executable, "scripts/demo_policy_loop.py", "--offline"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    duration = time.time() - t0
    demo_passed = (res.returncode == 0) and (duration < 120.0)
    print(f"       Demo finished with returncode={res.returncode} in {duration:.2f}s (Passed: {demo_passed})")

    print("[2/3] Checking that every path cited in documentation exists...")
    doc_paths_checked = {}
    all_paths_exist = True

    for doc_name in ["docs/POLICY_IMMUNE.md", "docs/DEMO_SCRIPT.md", "ENHANCEMENTS.md"]:
        doc_file = repo_root / doc_name
        checked = check_paths_cited_in_doc(doc_file)
        missing = [p for p, exists in checked.items() if not exists]
        doc_paths_checked[doc_name] = {
            "total_cited": len(checked),
            "all_exist": len(missing) == 0,
            "missing": missing,
            "details": checked,
        }
        if missing:
            all_paths_exist = False
            print(f"       WARNING in {doc_name}: Missing paths: {missing}")
        else:
            print(f"       SUCCESS in {doc_name}: All {len(checked)} cited paths exist.")

    print("[3/3] Running privacy and signature test suite...")
    t_test = time.time()
    res_test = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "backend/tests/test_immune_signatures.py"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    test_duration = time.time() - t_test
    privacy_tests_passed = (res_test.returncode == 0)
    print(f"       Privacy test suite finished with returncode={res_test.returncode} in {test_duration:.2f}s (Passed: {privacy_tests_passed})")

    acceptance_record = {
        "verified_at": round(time.time(), 3),
        "demo_execution": {
            "passed": demo_passed,
            "duration_seconds": round(duration, 3),
            "max_allowed_seconds": 120.0,
            "returncode": res.returncode,
        },
        "documentation_paths": {
            "all_paths_exist": all_paths_exist,
            "docs_evaluated": doc_paths_checked,
        },
        "privacy_tests": {
            "passed": privacy_tests_passed,
            "duration_seconds": round(test_duration, 3),
            "returncode": res_test.returncode,
        },
        "overall_status": "PASS" if (demo_passed and all_paths_exist and privacy_tests_passed) else "FAIL",
    }

    out_file = repo_root / "evidence" / "M6" / "acceptance_check.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(acceptance_record, f, indent=2)

    print(f"\nSaved acceptance results to {out_file}")
    print(f"OVERALL ACCEPTANCE STATUS: {acceptance_record['overall_status']}")
    if acceptance_record["overall_status"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
