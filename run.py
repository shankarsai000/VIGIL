"""VIGIL Entrypoint & Dynamic Port Runner.

Safely reads $PORT from the environment and launches Uvicorn.
Avoids shell variable expansion issues on container runtimes (Railway, Fly.io, Render).
"""

import os
import sys
import uvicorn

if __name__ == "__main__":
    raw_port = os.environ.get("PORT", "8000")
    try:
        port = int(raw_port)
    except (ValueError, TypeError):
        print(f"[VIGIL] Warning: PORT env var '{raw_port}' could not be parsed as int. Defaulting to 8000.")
        port = 8000

    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[VIGIL] Starting production server on {host}:{port} (PORT={port})")
    uvicorn.run("backend.main:app", host=host, port=port, reload=False, workers=1)
