"""VIGIL Plain-English Incident Explainer.

Translates complex security incidents into non-technical reports
by proxying requests through the central explainability_service.
"""

import logging
from typing import Any
from ..runtime.models import IncidentRecord
from ...services.explainability_service import explainability_service

logger = logging.getLogger("vigil.explainer")

class VIGILExplainer:
    """Explains technical AI agent vulnerabilities in human-readable plain English."""

    def __init__(self, config: Any):
        self.config = config
        logger.info("VIGILExplainer successfully wrapper-connected to central ExplainabilityService.")

    async def generate(self, incident: IncidentRecord) -> str:
        """Proxies incident explanation generation to the centralized explainability_service."""
        return await explainability_service.generate_explanation(incident)
