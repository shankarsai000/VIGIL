.PHONY: setup test verify evidence check clean help

help:
	@echo "VIGIL 2.0 Build & Governance Automation"
	@echo "Targets:"
	@echo "  setup    - Install Python and Node dependencies"
	@echo "  test     - Run offline test suites (pytest and frontend)"
	@echo "  verify   - Run live verification suites (ArmorIQ and Slack)"
	@echo "  evidence - Generate offline evidence vault bundles"
	@echo "  check    - Validate submission requirements (check_requirements.py)"
	@echo "  clean    - Remove temporary databases, caches, and test artifacts"

setup:
	uv pip install -r requirements.txt
	cd frontend && npm install

test:
	uv run pytest backend/tests/test_slack_approvals.py backend/tests/test_approval_containment.py backend/tests/test_immune_signatures.py backend/tests/test_evidence_vault.py backend/tests/test_submission_mode.py
	cd frontend && npm run build

verify:
	uv run python scripts/live_slack_verification.py

evidence:
	uv run python -c "from backend.app.evidence.bundle import export_evidence_bundle; export_evidence_bundle(output_dir='evidence/vault/sample_bundle')"
	uv run python verify_bundle.py evidence/vault/sample_bundle

check:
	uv run python scripts/check_requirements.py
