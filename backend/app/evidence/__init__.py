"""Evidence Vault package."""

from .bundle import (
    EvidenceVault,
    SecretsDetectedError,
    BundleExportError,
    extract_ledger_segment,
    build_config_snapshot,
    scan_for_secrets,
    get_or_create_vault_ed25519_key,
    canonical_json_bytes,
)

__all__ = [
    "EvidenceVault",
    "SecretsDetectedError",
    "BundleExportError",
    "extract_ledger_segment",
    "build_config_snapshot",
    "scan_for_secrets",
    "get_or_create_vault_ed25519_key",
    "canonical_json_bytes",
]
