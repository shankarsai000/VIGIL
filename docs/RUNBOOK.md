# VIGIL 2.0 Operational Runbook

This runbook outlines procedures for configuring, launching, validating, and auditing VIGIL 2.0.

---

## 1. Quickstart & Makefile Targets

For Linux/macOS environments with `make`, standard automation targets are defined in `Makefile`:

```bash
make setup      # Install dependencies (Python & Node)
make test       # Run offline unit and regression tests
make verify     # Execute live verification suites
make evidence   # Generate and verify tamper-proof evidence bundles
make check      # Validate requirements compliance
```

---

## 2. Windows PowerShell Equivalents

Since the development environment runs on Windows, the exact PowerShell commands corresponding to each Makefile target are:

### Setup (`make setup`)
```powershell
uv pip install -r requirements.txt
cd frontend ; npm install ; cd ..
```

### Test (`make test`)
```powershell
uv run pytest backend/tests/test_slack_approvals.py backend/tests/test_approval_containment.py backend/tests/test_immune_signatures.py backend/tests/test_evidence_vault.py
cd frontend ; npm run build ; cd ..
```

### Verify (`make verify`)
```powershell
# Requires live Slack credentials configured in .env
uv run python scripts/live_slack_verification.py
```

### Evidence (`make evidence`)
```powershell
uv run python -c "from backend.app.evidence.bundle import export_evidence_bundle; export_evidence_bundle(output_dir='evidence/vault/sample_bundle')"
uv run python verify_bundle.py evidence/vault/sample_bundle
```

### Check Requirements (`make check`)
```powershell
uv run python scripts/check_requirements.py
```

---

## 3. Running Locally

### Backend Service (FastAPI)
```powershell
# Set environment flags in .env or shell
$env:PORT = "8000"
$env:HOST = "0.0.0.0"
$env:ARMORIQ_MODE = "local-demo" # Or "live" with ARMORIQ_API_KEY
uv run uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Dashboard (Vite + React)
```powershell
cd frontend
npm run dev
# Dashboard available at http://localhost:5173
```

### Containment FastMCP Server (Port 8790)
```powershell
uv run python backend/app/policies/containment_mcp.py
```

### Tools FastMCP Server (Port 8791)
```powershell
uv run python demo/tools_mcp/server.py
```

---

## 4. Submission Mode (`SUBMISSION_MODE=1`)

To guarantee strict compliance during official hackathon evaluations and prevent accidental reliance on local mocks:

1. Set `SUBMISSION_MODE=1` in your environment or `.env`.
2. When `SUBMISSION_MODE=1`, VIGIL enforces:
   - `ARMORIQ_MODE` MUST be set to `live`.
   - If `ARMORIQ_MODE=local-demo` or `disabled`, the backend **refuses to start** with a fatal validation error.
   - All containment and policy proposals must resolve against the real ArmorIQ Policy Engine.

```powershell
$env:SUBMISSION_MODE = "1"
$env:ARMORIQ_MODE = "live"
uv run python scripts/check_requirements.py --submission
```
