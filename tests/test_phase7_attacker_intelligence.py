"""
Tests for Phase 7 Attacker Intelligence, AI Session Analysis, MITRE ATT&CK Mapping, and Advanced Analytics.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.gemini_session_analyst import GeminiSessionAnalyst
from backend.app.services.mitre_mapper import MitreMapper
from backend.app.services.persistence_service import PersistenceService


def test_mitre_mapper_techniques_for_intent():
    rec_techs = MitreMapper.get_techniques_for_intent("RECONNAISSANCE")
    assert len(rec_techs) > 0
    assert any(t["technique_id"] == "T1592" for t in rec_techs)
    assert rec_techs[0]["tactic"] == "Reconnaissance"

    disc_techs = MitreMapper.get_techniques_for_intent("DISCOVERY")
    assert len(disc_techs) > 0
    assert any(t["technique_id"] == "T1082" for t in disc_techs)


def test_mitre_mapper_session_mapping():
    session_doc = {
        "session_id": "test_sess_mitre_01",
        "dominant_intent": "CREDENTIAL_ACCESS",
        "intent_sequence": ["RECONNAISSANCE", "DISCOVERY", "CREDENTIAL_ACCESS"]
    }
    events = [
        {"command": "whoami", "intent": "RECONNAISSANCE"},
        {"command": "cat /etc/passwd", "intent": "DISCOVERY"},
        {"command": "cat /etc/shadow", "intent": "CREDENTIAL_ACCESS"}
    ]
    mapped = MitreMapper.map_session(session_doc, events)
    tech_ids = [t["technique_id"] for t in mapped]
    assert "T1592" in tech_ids or "T1082" in tech_ids or "T1003" in tech_ids


def test_gemini_session_analyst_deterministic_fallback():
    analyst = GeminiSessionAnalyst(enabled=False)
    session_doc = {
        "session_id": "sess_det_001",
        "dominant_intent": "DISCOVERY",
        "current_attack_stage": "DISCOVERY",
        "risk_score": 35,
        "source_ip": "10.10.10.5",
        "command_count": 3,
        "unique_commands": ["ls -la", "uname -a", "id"],
        "key_evidence": ["OS version fingerprinting"]
    }
    events = [
        {"timestamp": datetime.now(timezone.utc).isoformat(), "command": "uname -a", "intent": "RECONNAISSANCE"},
        {"timestamp": datetime.now(timezone.utc).isoformat(), "command": "ls -la", "intent": "DISCOVERY"},
    ]
    report = analyst.analyze_session(session_doc, events)
    assert report.session_id == "sess_det_001"
    assert report.source == "DETERMINISTIC_ANALYST"
    assert len(report.objective) > 0
    assert len(report.summary) > 0
    assert len(report.recommended_action) > 0


def test_api_session_analyze_and_mitre_endpoints():
    with TestClient(app) as client:
        # 1. Fetch sessions
        sessions_res = client.get("/api/sessions?limit=1")
        assert sessions_res.status_code == 200
        items = sessions_res.json()["items"]
        if not items:
            pytest.skip("No sessions present to test analyze endpoint")

        session_id = items[0]["session_id"]

        # 2. Analyze session
        analyze_res = client.post(f"/api/sessions/{session_id}/analyze")
        assert analyze_res.status_code == 200
        report = analyze_res.json()
        assert report["session_id"] == session_id
        assert "objective" in report
        assert "summary" in report
        assert "attack_progression" in report
        assert "threat_interpretation" in report
        assert "recommended_action" in report
        assert report["source"] in ["GEMINI_AI", "DETERMINISTIC_ANALYST"]

        # 3. MITRE mapping
        mitre_res = client.get(f"/api/sessions/{session_id}/mitre")
        assert mitre_res.status_code == 200
        mitre_data = mitre_res.json()
        assert isinstance(mitre_data, list)


def test_api_advanced_analytics_endpoints():
    with TestClient(app) as client:
        # Stages
        stages_res = client.get("/api/analytics/stages")
        assert stages_res.status_code == 200
        assert isinstance(stages_res.json(), list)

        # Risk distribution
        risk_dist_res = client.get("/api/analytics/risk-distribution")
        assert risk_dist_res.status_code == 200
        risk_data = risk_dist_res.json()
        assert len(risk_data) == 4
        assert risk_data[0]["range"].startswith("0-24")

        # Heatmap
        heatmap_res = client.get("/api/analytics/heatmap")
        assert heatmap_res.status_code == 200
        assert isinstance(heatmap_res.json(), list)
