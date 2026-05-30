import logging

logger = logging.getLogger("vigil.services.scoring")

class ScoringService:
    """Combines various security pipeline threat signals into a normalized integrated score."""

    def calculate_threat_score(
        self,
        rule_score: float,
        ewma_score: float,
        iforest_score: float,
        armorclaw_score: float
    ) -> float:
        """Legacy 4-layer scoring. Delegates to the v2 extended formula with zeroed new signals."""
        return self.calculate_threat_score_v2(
            rule_score=rule_score,
            ewma_score=ewma_score,
            iforest_score=iforest_score,
            armorclaw_score=armorclaw_score,
            prompt_mutation_score=0.0,
            capability_score=0.0,
            spoofing_score=0.0,
        )

    def calculate_threat_score_v2(
        self,
        rule_score: float,
        ewma_score: float,
        iforest_score: float,
        armorclaw_score: float,
        prompt_mutation_score: float = 0.0,
        capability_score: float = 0.0,
        spoofing_score: float = 0.0,
    ) -> float:
        """VIGIL 2.0 extended hybrid threat indexing formula:
        
        ThreatScore = (RuleScore * 0.30) 
                    + (EWMAAnomaly * 0.15) 
                    + (IsolationForest * 0.10) 
                    + (ArmorClawIntent * 0.20)
                    + (PromptMutation * 0.10)
                    + (CapabilityViolation * 0.10)
                    + (BehavioralSpoofing * 0.05)
                    
        Returns:
            A normalized float score between 0.0 and 1.0.
        """
        # Ensure raw inputs are normalized bounds
        r = max(0.0, min(1.0, float(rule_score)))
        e = max(0.0, min(1.0, float(ewma_score)))
        i = max(0.0, min(1.0, float(iforest_score)))
        a = max(0.0, min(1.0, float(armorclaw_score)))
        pm = max(0.0, min(1.0, float(prompt_mutation_score)))
        cv = max(0.0, min(1.0, float(capability_score)))
        bs = max(0.0, min(1.0, float(spoofing_score)))

        # Weighted calculation
        score = (r * 0.30) + (e * 0.15) + (i * 0.10) + (a * 0.20) + (pm * 0.10) + (cv * 0.10) + (bs * 0.05)
        
        # Override baseline dilution: if a rule signature or privilege escalation
        # is absolute (rule_score > 0.8), we ensure the final score maintains high visibility.
        if r > 0.8:
            score = max(score, r)

        # If a capability violation is detected (binary 1.0), ensure floor score
        if cv > 0.8:
            score = max(score, 0.75)

        final_score = max(0.0, min(1.0, float(score)))
        
        logger.info(
            f"[Scoring Service v2] Calculated Threat Score: {final_score:.4f} "
            f"(Rule={r:.2f}, EWMA={e:.2f}, IForest={i:.2f}, ArmorClaw={a:.2f}, "
            f"PromptMut={pm:.2f}, Capability={cv:.2f}, Spoofing={bs:.2f})"
        )
        return final_score

# Singleton service instance
scoring_service = ScoringService()
