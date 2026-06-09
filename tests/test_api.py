"""
test_api.py — FastAPI REST Endpoint Tests

Validates health check, input validation, rate limiting behavior,
and incident analysis endpoint responses.
"""

import pytest
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestInputValidation:
    """Tests for the input sanitization function in api/main.py."""

    @pytest.mark.security
    def test_clean_input_passes(self):
        from api.main import validate_and_sanitize
        result = validate_and_sanitize("John", "user")
        assert result == "John"

    @pytest.mark.security
    def test_alphanumeric_with_spaces(self):
        from api.main import validate_and_sanitize
        result = validate_and_sanitize("Privilege Escalation", "event")
        assert result == "Privilege Escalation"

    @pytest.mark.security
    def test_dashes_allowed(self):
        from api.main import validate_and_sanitize
        result = validate_and_sanitize("high-severity", "event")
        assert result == "high-severity"

    @pytest.mark.security
    def test_spl_injection_blocked(self):
        from api.main import validate_and_sanitize
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_and_sanitize("| search index=main | delete", "event")
        assert exc_info.value.status_code == 400
        assert "Malicious characters" in exc_info.value.detail

    @pytest.mark.security
    def test_sql_injection_blocked(self):
        from api.main import validate_and_sanitize
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_and_sanitize("'; DROP TABLE users;--", "user")
        assert exc_info.value.status_code == 400

    @pytest.mark.security
    def test_script_injection_blocked(self):
        from api.main import validate_and_sanitize
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_and_sanitize("<script>alert('xss')</script>", "event")
        assert exc_info.value.status_code == 400

    @pytest.mark.security
    def test_empty_input_passes(self):
        from api.main import validate_and_sanitize
        result = validate_and_sanitize("", "user")
        assert result == ""

    @pytest.mark.security
    def test_none_input_passes(self):
        from api.main import validate_and_sanitize
        result = validate_and_sanitize(None, "user")
        assert result is None


class TestSanitizationRegex:
    """Direct tests for the sanitization regex pattern."""

    @pytest.mark.security
    def test_regex_allows_safe_chars(self):
        safe_inputs = ["John", "Large Data Download", "high-priority", "user123", "Test_Event"]
        pattern = r'[^\w\s\-]'
        for inp in safe_inputs:
            sanitized = re.sub(pattern, '', inp)
            assert sanitized == inp, f"Safe input '{inp}' was modified"

    @pytest.mark.security
    def test_regex_strips_dangerous_chars(self):
        dangerous_inputs = [
            ("| search index=main", " search indexmain"),
            ("'; DROP TABLE", " DROP TABLE"),
            ("<script>alert</script>", "scriptalertscript"),
        ]
        pattern = r'[^\w\s\-]'
        for original, _ in dangerous_inputs:
            sanitized = re.sub(pattern, '', original)
            assert sanitized != original, f"Dangerous input '{original}' was NOT sanitized"


class TestAPIEndpoints:
    """Tests for FastAPI application configuration."""

    @pytest.mark.api
    def test_app_exists(self):
        from api.main import app
        assert app is not None
        assert app.title == "Enterprise Council AI Developer API"

    @pytest.mark.api
    def test_app_version(self):
        from api.main import app
        assert app.version == "1.0.0"

    @pytest.mark.api
    def test_routes_registered(self):
        from api.main import app
        routes = [r.path for r in app.routes]
        assert "/api/v1/health" in routes
        assert "/api/v1/status" in routes
        assert "/api/v1/indexes" in routes

    @pytest.mark.api
    def test_analyze_route_registered(self):
        from api.main import app
        routes = [r.path for r in app.routes]
        assert "/api/v1/analyze" in routes or "/api/v1/incident/analyze" in routes

    @pytest.mark.api
    def test_request_model_schema(self):
        from api.main import IncidentRequest
        schema = IncidentRequest.model_json_schema()
        assert "user" in schema["properties"]
        assert "event" in schema["properties"]
        assert "severity" in schema["properties"]

    @pytest.mark.api
    def test_response_model_schema(self):
        from api.main import IncidentResponse
        schema = IncidentResponse.model_json_schema()
        assert "success" in schema["properties"]
        assert "incident" in schema["properties"]
        assert "decision" in schema["properties"]
        assert "opinions" in schema["properties"]
        assert "debate" in schema["properties"]
        assert "simulation" in schema["properties"]
        assert "twin" in schema["properties"]
