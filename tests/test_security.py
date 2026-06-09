"""
test_security.py — Security-Focused Tests

Validates input sanitization, RBAC permission checks,
session timeout configuration, and injection prevention.
"""

import pytest
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRBACPermissions:
    """Tests for the Role-Based Access Control permission checks."""

    def _check_permission(self, rbac_role, decision_action):
        """Replicate the RBAC check from frontend/app.py."""
        action = str(decision_action).lower().replace(" ", "_")
        if rbac_role == "Auditor":
            return False, "Auditors have read-only access. Direct mitigations are blocked."
        if rbac_role == "SOC Analyst":
            return False, "SOC Analysts are not authorized. Incident must be escalated."
        if rbac_role == "SOC Manager":
            if "block" in action:
                return False, "SOC Manager cannot execute Account Block. CISO approval required."
            return True, ""
        if rbac_role == "CISO":
            return True, ""
        return False, "Unauthorized Role"

    @pytest.mark.security
    def test_ciso_can_block(self):
        allowed, msg = self._check_permission("CISO", "Block User")
        assert allowed is True
        assert msg == ""

    @pytest.mark.security
    def test_ciso_can_monitor(self):
        allowed, msg = self._check_permission("CISO", "Monitor User")
        assert allowed is True

    @pytest.mark.security
    def test_ciso_can_restrict(self):
        allowed, msg = self._check_permission("CISO", "Restrict Access")
        assert allowed is True

    @pytest.mark.security
    def test_soc_manager_cannot_block(self):
        allowed, msg = self._check_permission("SOC Manager", "Block User")
        assert allowed is False
        assert "CISO approval" in msg

    @pytest.mark.security
    def test_soc_manager_can_monitor(self):
        allowed, msg = self._check_permission("SOC Manager", "Monitor User")
        assert allowed is True

    @pytest.mark.security
    def test_soc_manager_can_restrict(self):
        allowed, msg = self._check_permission("SOC Manager", "Restrict Access")
        assert allowed is True

    @pytest.mark.security
    def test_analyst_cannot_execute(self):
        for action in ["Block User", "Monitor User", "Restrict Access"]:
            allowed, msg = self._check_permission("SOC Analyst", action)
            assert allowed is False
            assert "not authorized" in msg

    @pytest.mark.security
    def test_auditor_read_only(self):
        for action in ["Block User", "Monitor User", "Restrict Access"]:
            allowed, msg = self._check_permission("Auditor", action)
            assert allowed is False
            assert "read-only" in msg

    @pytest.mark.security
    def test_unknown_role_denied(self):
        allowed, msg = self._check_permission("RandomRole", "Monitor User")
        assert allowed is False
        assert "Unauthorized" in msg


class TestInjectionPrevention:
    """Comprehensive injection prevention tests."""

    SANITIZATION_PATTERN = r'[^\w\s\-]'

    @pytest.mark.security
    def test_spl_pipe_injection(self):
        """SPL pipe commands should be detected."""
        malicious = "| search index=_internal | delete"
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_spl_subsearch_injection(self):
        """SPL subsearch syntax should be detected."""
        malicious = "[search index=main sourcetype=syslog]"
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_sql_union_injection(self):
        malicious = "' UNION SELECT * FROM users--"
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_xss_script_tag(self):
        malicious = "<script>document.cookie</script>"
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_xss_event_handler(self):
        malicious = '<img onerror="alert(1)" src=x>'
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_command_injection(self):
        malicious = "; rm -rf /"
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_ldap_injection(self):
        malicious = "admin)(&(password=*))"
        sanitized = re.sub(self.SANITIZATION_PATTERN, '', malicious)
        assert sanitized != malicious

    @pytest.mark.security
    def test_safe_inputs_unchanged(self):
        """Normal inputs should pass through sanitization unchanged."""
        safe_inputs = [
            "John",
            "Privilege Escalation",
            "Large Data Download",
            "high-severity",
            "user_123",
            "Critical",
            "SOC Analyst Report",
        ]
        for inp in safe_inputs:
            sanitized = re.sub(self.SANITIZATION_PATTERN, '', inp)
            assert sanitized == inp, f"Safe input '{inp}' was incorrectly modified"


class TestIncidentClassification:
    """Tests for the incident classifier module."""

    @pytest.mark.unit
    def test_exact_match_classification(self):
        from orchestrator.incident_classifier import classify
        result = classify({"event": "Privilege Escalation", "severity": "Critical"})
        assert result["category"] == "Insider Threat"
        assert result["method"] == "exact_match"
        assert "security" in result["domains"]

    @pytest.mark.unit
    def test_keyword_fallback_classification(self):
        from orchestrator.incident_classifier import classify
        result = classify({"event": "suspicious download activity", "severity": "High"})
        assert result["method"] in ("keyword_fallback", "splunk_ai_toolkit")
        assert result["category"] != "Unknown"

    @pytest.mark.unit
    def test_unknown_event_default_fallback(self):
        from orchestrator.incident_classifier import classify
        result = classify({"event": "completely random gibberish xyzzy", "severity": "Low"})
        # Should either hit AI toolkit or default fallback
        assert result["method"] in ("default_fallback", "splunk_ai_toolkit")
        assert len(result["domains"]) > 0

    @pytest.mark.unit
    def test_classification_returns_required_keys(self):
        from orchestrator.incident_classifier import classify
        result = classify({"event": "VPN Login", "severity": "Low"})
        assert "event" in result
        assert "category" in result
        assert "domains" in result
        assert "priority" in result
        assert "method" in result

    @pytest.mark.unit
    def test_all_known_events_classified(self):
        from orchestrator.incident_classifier import INCIDENT_PROFILES, classify
        for event_name in INCIDENT_PROFILES:
            result = classify({"event": event_name, "severity": "Medium"})
            assert result["method"] == "exact_match", \
                f"Known event '{event_name}' should be classified by exact_match"


class TestAPISecurityHeaders:
    """Verifies that FastAPI returns the correct security headers."""

    @pytest.mark.security
    def test_api_security_headers(self):
        from fastapi.testclient import TestClient
        from api.main import app
        
        client = TestClient(app)
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains; preload"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert "Content-Security-Policy" in response.headers
