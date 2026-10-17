"""Requirements verification script (Phase R0).

Parses docs/brief/REQUIREMENTS.md, validates that all PASS items have existing
evidence paths on disk, and flags any NOT STARTED items when run in submission mode.
"""
import os
import re
import sys
from typing import Dict, List, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def parse_requirements_md(path: str) -> List[Dict[str, str]]:
    if not os.path.isfile(path):
        print(f"ERROR: Requirements file not found: {path}")
        sys.exit(1)

    items = []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_section = ""
    for line in lines:
        line_s = line.strip()
        if line_s.startswith("## "):
            current_section = line_s
            continue

        if not line_s.startswith("|"):
            continue

        parts = [p.strip() for p in line_s.split("|")[1:-1]]
        if len(parts) < 4:
            continue

        item_id = parts[0].replace("*", "")
        if not (item_id.startswith("BR-") or item_id.startswith("PK-") or item_id.startswith("IN-")):
            continue

        # Extract status (last column)
        status = parts[-1].replace("*", "").strip().upper()
        
        # Extract evidence paths
        evidence_text = parts[3] if len(parts) >= 4 else ""
        paths = re.findall(r"\[.*?\]\((file:///[^)]+|[^)]+)\)", evidence_text)
        if not paths:
            # Fallback for plain backtick paths
            paths = re.findall(r"`([^`]+)`", evidence_text)

        cleaned_paths = []
        for p in paths:
            p_clean = p.replace("file:///", "").replace("file://", "")
            # Remove line number anchor (#L...)
            if "#" in p_clean:
                p_clean = p_clean.split("#")[0]
            # Normalize drive letters on Windows (e.g. d:/vigil-v2 -> d:\vigil-v2)
            cleaned_paths.append(p_clean)

        items.append({
            "id": item_id,
            "section": current_section,
            "status": status,
            "raw_evidence": evidence_text,
            "paths": cleaned_paths,
            "row": line_s,
        })

    return items


def verify_evidence_path(p: str) -> bool:
    # If path is a test or method reference without file extension, skip file check
    if not ("." in os.path.basename(p) or "/" in p or "\\" in p):
        return True

    # Check relative to repo root
    if os.path.exists(p):
        return True
    
    # Try normalizing path relative to current directory
    norm = os.path.normpath(p)
    if os.path.exists(norm):
        return True

    # Strip workspace prefix if absolute
    for prefix in ["d:/vigil-v2/vigil-v2/", "d:\\vigil-v2\\vigil-v2\\"]:
        if p.lower().startswith(prefix.lower()):
            rel = p[len(prefix):]
            if os.path.exists(rel):
                return True

    return False


def main():
    is_submission = "--submission" in sys.argv or os.environ.get("SUBMISSION_MODE") == "1"
    req_file = "docs/brief/REQUIREMENTS.md"
    items = parse_requirements_md(req_file)

    print("=" * 68)
    print("VIGIL 2.0 -- REQUIREMENTS COMPLIANCE CHECKER")
    print(f"Mode: {'SUBMISSION GATE' if is_submission else 'BASELINE AUDIT'}")
    print("=" * 68)

    counts = {"PASS": 0, "IN PROGRESS": 0, "NOT STARTED": 0, "BLOCKED": 0, "FAIL": 0}
    missing_evidence = []
    not_started_items = []

    for item in items:
        status = item["status"]
        if status in counts:
            counts[status] += 1
        else:
            counts["FAIL"] += 1

        if status == "NOT STARTED":
            not_started_items.append(item["id"])

        if status == "PASS":
            for path in item["paths"]:
                if not verify_evidence_path(path):
                    missing_evidence.append((item["id"], path))

    # Print summary table
    print(f"\nItem Count: {len(items)}")
    for status, cnt in counts.items():
        print(f"  {status:<15}: {cnt}")

    print("\nDetailed Status:")
    for item in items:
        badge = f"[{item['status']}]"
        print(f"  {item['id']:<8} {badge:<15} {item['raw_evidence'][:42]}")

    failed = False
    if missing_evidence:
        print("\nERROR: PASS items missing evidence on disk:")
        for i_id, path in missing_evidence:
            print(f"  - {i_id}: {path}")
        failed = True

    if is_submission and not_started_items:
        print("\nERROR: NOT STARTED items present at submission time:")
        for i_id in not_started_items:
            print(f"  - {i_id}")
        failed = True

    print("\n" + "=" * 68)
    if failed:
        print("VERIFICATION: FAIL")
        sys.exit(1)
    else:
        print("VERIFICATION: PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
