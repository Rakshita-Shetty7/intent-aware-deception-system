"""
Hybrid Intent Classifier Service.
Arbitrates between deterministic Rule Engine and Gemini LLM intelligence, consolidating evidence.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from backend.app.config import settings
from backend.app.models.events import NormalizedEvent
from backend.app.models.features import SessionFeatures
from backend.app.models.intent import (
    AttackStage,
    ClassificationSource,
    HybridClassification,
    IntentCategory,
)
from backend.app.services.gemini_classifier import GeminiClassifier
from backend.app.services.rule_classifier import RuleClassifier

logger = logging.getLogger(__name__)


class HybridClassifier:
    """
    Hybrid classification engine coordinating deterministic heuristics with LLM contextual reasoning.
    """

    def __init__(
        self,
        rule_classifier: Optional[RuleClassifier] = None,
        gemini_classifier: Optional[GeminiClassifier] = None,
        rule_confidence_threshold: float = 0.90
    ):
        self.rule_classifier = rule_classifier or RuleClassifier()
        self.gemini_classifier = gemini_classifier or GeminiClassifier()
        self.rule_confidence_threshold = rule_confidence_threshold

    def classify(
        self,
        event: NormalizedEvent,
        session_features: Optional[SessionFeatures] = None
    ) -> HybridClassification:
        """
        Classifies an incoming event using the hybrid decision arbitration pipeline.
        """
        rule_result = None
        if settings.RULE_ENGINE_ENABLED:
            rule_result = self.rule_classifier.classify(event, session_features)

        # Determine whether to query Gemini
        # Only query Gemini if:
        # 1. Gemini is enabled
        # 2. A command is present (or novel complex event)
        # 3. AND (rule confidence is low < 0.85 OR rule intent is OTHER)
        has_command = event.command is not None and len(event.command.strip()) > 0
        should_query_gemini = (
            self.gemini_classifier.enabled
            and has_command
            and (
                rule_result is None
                or rule_result.confidence < self.rule_confidence_threshold
                or rule_result.intent == IntentCategory.OTHER
            )
        )

        ai_result = None
        if should_query_gemini:
            ai_result = self.gemini_classifier.classify(event, session_features)

        # Decision arbitration
        if ai_result is not None:
            # Gemini succeeded
            source = ClassificationSource.HYBRID if (rule_result and rule_result.rule_matches) else ClassificationSource.GEMINI
            
            # If rule had high confidence on a known signature, preserve rule intent if AI is uncertain
            if rule_result and rule_result.confidence >= 0.85 and ai_result.confidence < 0.70:
                final_intent = rule_result.intent
                final_stage = rule_result.attack_stage
                final_confidence = rule_result.confidence
            else:
                final_intent = ai_result.intent
                final_stage = ai_result.attack_stage
                final_confidence = ai_result.confidence

            classification = HybridClassification(
                intent=final_intent,
                attack_stage=final_stage,
                confidence=round(final_confidence, 2),
                source=source,
                rule_evidence=rule_result.evidence if rule_result else [],
                ai_reason=ai_result.reason,
                ai_evidence=ai_result.evidence,
                timestamp=datetime.now(timezone.utc)
            )
        elif rule_result is not None:
            # Rule engine result (either Gemini disabled, skipped, or failed gracefully)
            source = ClassificationSource.FALLBACK if should_query_gemini else ClassificationSource.RULE
            classification = HybridClassification(
                intent=rule_result.intent,
                attack_stage=rule_result.attack_stage,
                confidence=round(rule_result.confidence, 2),
                source=source,
                rule_evidence=rule_result.evidence,
                ai_reason=None,
                ai_evidence=[],
                timestamp=datetime.now(timezone.utc)
            )
        else:
            # Pure default fallback
            classification = HybridClassification(
                intent=IntentCategory.OTHER,
                attack_stage=AttackStage.UNKNOWN,
                confidence=0.10,
                source=ClassificationSource.FALLBACK,
                rule_evidence=["Both rule engine and AI classifier unavailable"],
                ai_reason=None,
                ai_evidence=[],
                timestamp=datetime.now(timezone.utc)
            )

        logger.info(
            "[CLASSIFICATION] session=%s intent=%s stage=%s source=%s confidence=%.2f",
            event.session_id,
            classification.intent,
            classification.attack_stage,
            classification.source,
            classification.confidence
        )

        return classification
