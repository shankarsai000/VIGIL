"""Deterministic Tool Output Scanner (Phase V4).

Scans outputs returned from executed tools for indirect prompt injections:
- Role markers (e.g. `<system>`, `[SYSTEM]`, `Assistant:`, `### System:`)
- Instruction override phrasing ("ignore previous instructions", "disregard prior")
- Hidden markup (zero-width spaces, hidden HTML comments, ANSI sequences)
- Obfuscated base64 blobs in text fields

CRITICAL INVARIANT (Rule A):
A flagged tool output NEVER blocks the tool call or agent execution on its own.
Instead, it elevates the child span's lineage taint to EXTERNAL_UNTRUSTED via V1 DIFC,
allowing ArmorIQ to enforce policies downstream when the tainted data reaches restricted sinks.
"""

from __future__ import annotations

import abc
import base64
import re
from typing import Any, Dict, List, Optional, Tuple

from ..provenance.lineage import ProvenanceTracker, TaintLevel


class ToolOutputClassifierInterface(abc.ABC):
    """Stage 2 optional ML classifier interface (no weights bundled)."""

    @abc.abstractmethod
    def predict(self, text: str) -> float:
        """Returns indirect injection probability score (0.0 to 1.0)."""
        pass


class DeterministicOutputScanner:
    """Stage 1 deterministic pattern and heuristic tool output scanner."""

    ROLE_MARKER_PATTERNS = [
        re.compile(r"(?i)<\s*system\s*>", re.IGNORECASE),
        re.compile(r"(?i)\[\s*system\s*\]", re.IGNORECASE),
        re.compile(r"(?i)^human:\s*", re.MULTILINE),
        re.compile(r"(?i)^assistant:\s*", re.MULTILINE),
        re.compile(r"(?i)###\s*system\s*:", re.IGNORECASE),
        re.compile(r"(?i)<\s*im_start\s*>", re.IGNORECASE),
        re.compile(r"(?i)<\s*im_end\s*>", re.IGNORECASE),
    ]

    OVERRIDE_PATTERNS = [
        re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts|directives)"),
        re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts|rules)"),
        re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|guidelines)"),
        re.compile(r"(?i)new\s+system\s+(?:instructions|prompt)\s*:"),
        re.compile(r"(?i)you\s+are\s+now\s+in\s+developer\s+mode"),
        re.compile(r"(?i)bypass\s+(?:all\s+)?(?:security|guardrails|filters)"),
    ]

    HIDDEN_MARKUP_PATTERNS = [
        re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]"),  # Zero-width / bidi chars
        re.compile(r"<!--[\s\S]*?-->"),  # Invisible markdown / HTML comments
        re.compile(r"\x1b\[[0-9;]*[a-zA-Z]"),  # ANSI escape codes
    ]

    BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

    def scan_text(self, text: str) -> Tuple[bool, List[str]]:
        """Inspect text for injection signatures. Returns (is_flagged, detected_categories)."""
        if not text or not isinstance(text, str):
            return False, []

        categories = []

        # 1. Role markers
        for pat in self.ROLE_MARKER_PATTERNS:
            if pat.search(text):
                categories.append("ROLE_MARKER")
                break

        # 2. Override phrasing
        for pat in self.OVERRIDE_PATTERNS:
            if pat.search(text):
                categories.append("INSTRUCTION_OVERRIDE")
                break

        # 3. Hidden markup
        for pat in self.HIDDEN_MARKUP_PATTERNS:
            if pat.search(text):
                categories.append("HIDDEN_MARKUP")
                break

        # 4. Obfuscated Base64 blobs
        for match in self.BASE64_PATTERN.finditer(text):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate, validate=True)
                # If decoded bytes contains readable ascii instructions, flag
                if len(decoded) >= 24 and any(b >= 32 and b <= 126 for b in decoded):
                    categories.append("SUSPICIOUS_BASE64_BLOB")
                    break
            except Exception:
                pass

        return len(categories) > 0, categories

    def scan_and_taint_lineage(
        self,
        output_payload: Any,
        trace_id: str,
        to_agent: str,
        tracker: ProvenanceTracker,
        source_label: str = "tool_output",
    ) -> Dict[str, Any]:
        """Scan tool output and conditionally apply taint to downstream agent span.
        
        Rule A: Does NOT block tool call. Elevates taint to EXTERNAL_UNTRUSTED if flagged.
        """
        text_content = str(output_payload)
        is_flagged, categories = self.scan_text(text_content)

        assigned_taint = TaintLevel.EXTERNAL_UNTRUSTED if is_flagged else TaintLevel.VERIFIED_INTERNAL

        record = tracker.record_input(
            trace_id=trace_id,
            to_agent=to_agent,
            input_taint=assigned_taint,
            source_label=f"{source_label}_{'_'.join(categories)}" if is_flagged else source_label,
        )

        return {
            "flagged": is_flagged,
            "categories": categories,
            "assigned_taint": assigned_taint.name,
            "span_id": record.span_id,
            "blocked": False,  # Explicit proof: never blocks client-side
        }


# Global singleton scanner
output_scanner = DeterministicOutputScanner()
