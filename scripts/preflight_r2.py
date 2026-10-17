"""Phase R2 Preflight script.

Checks credential presence and lengths without printing secrets.
Records flags for armoriq CLI commands.
Outputs evidence/R2/preflight.json.
"""

from __future__ import annotations

import json
import os
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


def run_cmd(args: list[str]) -> str:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    res = subprocess.run(args, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
    return res.stdout.strip()


def main():
    vals = dotenv_values(REPO_ROOT / ".env")
    api_key = vals.get("ARMORIQ_API_KEY", "")
    user_email = vals.get("ARMORIQ_USER_EMAIL", "")

    if not api_key or not user_email:
        print("BLOCKED: ARMORIQ_API_KEY and ARMORIQ_USER_EMAIL must be set in .env")
        sys.exit(1)

    armoriq_help = run_cmd([sys.executable, "-m", "armoriq_sdk.cli", "--help"])
    validate_help = run_cmd([sys.executable, "-m", "armoriq_sdk.cli", "validate", "--help"])
    register_help = run_cmd([sys.executable, "-m", "armoriq_sdk.cli", "register", "--help"])

    preflight_data = {
        "status": "PASS",
        "credentials": {
            "api_key_present": bool(api_key),
            "api_key_length": len(api_key),
            "user_email_present": bool(user_email),
            "user_email_length": len(user_email),
            "user_email_domain": user_email.split("@")[-1] if "@" in user_email else "unknown",
        },
        "cli_flags": {
            "validate": ["--config CONFIG"],
            "register": ["--config CONFIG", "--dry-run"],
        },
        "cli_help_summaries": {
            "main": armoriq_help.splitlines()[0] if armoriq_help else "",
            "validate": validate_help.splitlines()[0] if validate_help else "",
            "register": register_help.splitlines()[0] if register_help else "",
        },
    }

    out_file = REPO_ROOT / "evidence" / "R2" / "preflight.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(preflight_data, f, indent=2)

    print(f"Preflight completed successfully -> {out_file}")


if __name__ == "__main__":
    main()
