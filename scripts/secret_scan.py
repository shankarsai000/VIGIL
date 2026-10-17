"""Secret Scan Script for Submission Compliance (Phase F1).

Scans:
1. All repository files (excluding .env and .git).
2. Git commit history since baseline commit 6942674d.

Checks for:
- API key patterns (ak_, sk-, xoxb-, xapp-).
- Literal secret values defined in .env.

Saves results to evidence/F1/secret_scan.txt.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from dotenv import dotenv_values

REPO_ROOT = Path(__file__).resolve().parent.parent

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def run_secret_scan():
    print("[Secret Scan] Loading secrets to check from .env...")
    env_path = REPO_ROOT / ".env"
    env_vals = dotenv_values(env_path) if env_path.exists() else {}

    sensitive_keys = {
        "ARMORIQ_API_KEY",
        "OPERATOR_API_KEY",
        "CONTAINMENT_SECRET",
        "ANTHROPIC_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "SLACK_BOT_TOKEN",
        "SLACK_SIGNING_SECRET",
        "SLACK_APP_TOKEN",
    }

    secret_literals = []
    for k, v in env_vals.items():
        if k in sensitive_keys and v and len(v) >= 8:
            secret_literals.append((k, v))

    print(f"[Secret Scan] Checking {len(secret_literals)} sensitive credentials against tracked files and git history...")

    hits = []

    # 1. Get all tracked files via git ls-files
    res = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8")
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    patterns = [
        ("AK_PATTERN", re.compile(r"\bak_[a-zA-Z0-9]{20,}\b")),
        ("SK_PATTERN", re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b")),
        ("SLACK_BOT_PATTERN", re.compile(r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}\b")),
        ("SLACK_APP_PATTERN", re.compile(r"\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,}\b")),
    ]

    for rel_path in tracked_files:
        if rel_path in [".env", ".env.example"]:
            continue
        file_path = REPO_ROOT / rel_path
        if not file_path.exists() or file_path.is_dir():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # Check literal matches
            for key_name, lit_val in secret_literals:
                if lit_val in content:
                    hits.append((rel_path, f"LITERAL_SECRET:{key_name}"))
            # Check patterns
            for pat_name, pat in patterns:
                if pat.search(content):
                    hits.append((rel_path, pat_name))
        except Exception:
            pass

    # 2. Check git log since baseline commit
    baseline = "6942674d"
    log_cmd = ["git", "log", f"{baseline}..HEAD", "-p"]
    log_res = subprocess.run(log_cmd, cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    if log_res.returncode == 0:
        log_diff = log_res.stdout
        for key_name, lit_val in secret_literals:
            if lit_val in log_diff:
                hits.append(("git_history", f"LITERAL_SECRET_IN_DIFF:{key_name}"))
        for pat_name, pat in patterns:
            if pat.search(log_diff):
                hits.append(("git_history", f"PATTERN_IN_DIFF:{pat_name}"))

    status = "CLEAN" if len(hits) == 0 else "FAIL"
    print(f"[Secret Scan] Total hits: {len(hits)} -> Status: {status}")

    for out_rel in ["evidence/F1/secret_scan.txt", "evidence/VF/secret_scan.txt"]:
        out_file = REPO_ROOT / out_rel
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"STATUS: {status}\n")
            f.write(f"TOTAL_HITS: {len(hits)}\n")
            f.write(f"BASELINE_COMMIT: {baseline}\n")
            f.write(f"TRACKED_FILES_SCANNED: {len(tracked_files)}\n\n")
            if hits:
                f.write("FINDINGS:\n")
                for h in hits:
                    f.write(f"  {h[0]}: {h[1]}\n")
            else:
                f.write("No secrets detected across tracked files or git history since baseline.\n")
        print(f"[Secret Scan] Output saved to: {out_file}")
    if hits:
        sys.exit(1)


if __name__ == "__main__":
    run_secret_scan()
