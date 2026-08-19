"""
Unit tests for HybridClassifier service.
"""

from datetime import datetime, timezone
import json
from unittest.mock import MagicMock
import pytest

from backend.app.models.events import NormalizedEvent
from backend.app.models.intent import AttackStage, ClassificationSource, IntentCategory
from backend.app.services.gemini_classifier import GeminiClassifier
from backend.app.services.hybrid_classifier import HybridClassifier
from backend.app.services.rule_classifier import RuleClassifier


def make_event(command: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test_ev_hyb",
        timestamp=datetime.now(timezone.utc),
        session_id="test_sess_hyb",
        event_type="command_input",
        command=command
    )


def test_hybrid_high_confidence_rule_fast_path():
    # whoami is a high-confidence rule (>0.85)
    rule_classifier = RuleClassifier()
    # Gemini mock should not need to override
    gemini_classifier = GeminiClassifier(enabled=False)

    hybrid = HybridClassifier(
        rule_classifier=rule_classifier,
        gemini_classifier=gemini_classifier
    )

    res = hybrid.classify(make_event("whoami"))
    assert res.intent == IntentCategory.RECONNAISSANCE
    assert res.attack_stage == AttackStage.RECONNAISSANCE
    assert res.source == ClassificationSource.RULE
    assert len(res.rule_evidence) > 0


def test_hybrid_invokes_gemini_on_novel_command():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "intent": "EXPLOITATION",
        "attack_stage": "EXECUTION",
        "confidence": 0.94,
        "reason": "Obfuscated shell payload exploiting memory bug",
        "evidence": ["base64 payload", "eval loop"]
    })
    mock_client.models.generate_content.return_value = mock_response

    rule_classifier = RuleClassifier()
    gemini_classifier = GeminiClassifier(api_key="valid", enabled=True, client=mock_client)

    hybrid = HybridClassifier(
        rule_classifier=rule_classifier,
        gemini_classifier=gemini_classifier
    )

    # Obscure novel command that rules classify as OTHER
    res = hybrid.classify(make_event("eval $(echo aGVsbG8= | base64 -d)"))
    assert res.intent == IntentCategory.EXPLOITATION
    assert res.attack_stage == AttackStage.EXECUTION
    assert res.source in (ClassificationSource.GEMINI, ClassificationSource.HYBRID)
    assert res.ai_reason is not None


def test_hybrid_graceful_fallback_when_gemini_fails():
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception("503 Service Unavailable")

    rule_classifier = RuleClassifier()
    gemini_classifier = GeminiClassifier(api_key="valid", enabled=True, client=mock_client)

    hybrid = HybridClassifier(
        rule_classifier=rule_classifier,
        gemini_classifier=gemini_classifier,
        rule_confidence_threshold=0.99  # Force attempting Gemini
    )

    # When Gemini fails, it should fall back safely to the rule engine result
    res = hybrid.classify(make_event("id"))
    assert res.intent == IntentCategory.RECONNAISSANCE
    assert res.source == ClassificationSource.FALLBACK
    assert len(res.rule_evidence) > 0
