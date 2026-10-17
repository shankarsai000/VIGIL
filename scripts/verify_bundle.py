"""Forwarding wrapper for verify_bundle.py in scripts/."""
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from verify_bundle import main

if __name__ == "__main__":
    main()
