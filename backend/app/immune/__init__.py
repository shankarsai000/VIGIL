"""VIGIL Policy Immune System module."""
from .records import ActionRecord, compute_arg_shape
from .replay import (
    CandidateRule,
    ReplayReport,
    ReplayAssumptions,
    ReplayEngine,
    compute_false_block_upper,
    evaluate_candidate_rule,
)
from .candidates import (
    AttackFamilyCandidate,
    extract_candidates,
    STATUS_ACCEPT,
    STATUS_INSUFFICIENT_EVIDENCE,
    STATUS_REJECT,
    STATUS_NOT_ENFORCEABLE,
)
from .compiler import (
    ImpactTier,
    PolicyProposal,
    CompiledArtifacts,
    ApprovalError,
    compile_agent_policy,
    execute_compile,
)

__all__ = [
    "ActionRecord",
    "compute_arg_shape",
    "CandidateRule",
    "ReplayReport",
    "ReplayAssumptions",
    "ReplayEngine",
    "compute_false_block_upper",
    "evaluate_candidate_rule",
    "AttackFamilyCandidate",
    "extract_candidates",
    "STATUS_ACCEPT",
    "STATUS_INSUFFICIENT_EVIDENCE",
    "STATUS_REJECT",
    "STATUS_NOT_ENFORCEABLE",
    "ImpactTier",
    "PolicyProposal",
    "CompiledArtifacts",
    "ApprovalError",
    "compile_agent_policy",
    "execute_compile",
]
