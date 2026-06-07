"""
api/main.py — Developer REST API for Enterprise Council AI

Exposes the Multi-Agent Incident Response pipeline as a REST service
so third-party developer apps can easily integrate decision intelligence.
"""

import os
import sys
import re
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.workflow import run_council

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Enterprise Council AI Developer API",
    description="Developer endpoints to run the multi-agent incident response consensus loop.",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
)


# HTTPS Enforcement Middleware
ENABLE_HTTPS = os.environ.get("ENABLE_HTTPS", "false").lower() == "true"
if ENABLE_HTTPS or (os.path.exists("api/key.pem") and os.path.exists("api/cert.pem")):
    app.add_middleware(HTTPSRedirectMiddleware)



class IncidentRequest(BaseModel):
    user: str = Field(..., example="John", description="The target username or entity involved in the incident")
    event: str = Field(..., example="Privilege Escalation", description="The security event type (e.g. Large Data Download, Privilege Escalation)")
    severity: str = Field(default="Medium", example="Critical", description="Severity level of the event (Critical, High, Medium, Low)")


class IncidentResponse(BaseModel):
    success: bool
    incident: Dict[str, Any]
    decision: Dict[str, Any]
    opinions: list
    debate: Dict[str, Any]
    simulation: Dict[str, Any]
    twin: Dict[str, Any]


@app.get("/api/v1/health")
def health_check():
    """Verify system connectivity and modules status."""
    from splunk.splunk_client import get_client
    client = get_client()
    is_live = type(client).__name__ in ["SplunkClient", "SplunkSDKClient"]
    return {
        "status": "healthy",
        "splunk_connected": is_live,
        "splunk_mode": "Live REST/SDK" if is_live else "Local CSV Fallback",
        "hosted_models": "Ready"
    }


@app.get("/api/v1/status")
def status_check():
    """Alias for health check to verify system connectivity."""
    return health_check()


@app.get("/api/v1/indexes")
def list_indexes():
    """List active Splunk indexes and their statuses."""
    import json
    from splunk.splunk_client import get_client
    client = get_client()
    if hasattr(client, "_request") and type(client).__name__ not in ["LocalSplunkClient"]:
        try:
            res = client._request("GET", "/services/data/indexes?output_mode=json")
            data = json.loads(res)
            indexes = []
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                indexes.append({
                    "name": entry.get("name"),
                    "totalEventCount": content.get("totalEventCount", 0),
                    "disabled": content.get("disabled", False)
                })
            return {"indexes": indexes, "live_connection": True}
        except Exception:
            pass
            
    # Fallback/CSV Mode
    return {
        "indexes": [
            {"name": "security", "disabled": False, "totalEventCount": 46},
            {"name": "infrastructure", "disabled": False, "totalEventCount": 44},
            {"name": "business", "disabled": False, "totalEventCount": 33},
            {"name": "compliance", "disabled": False, "totalEventCount": 38}
        ],
        "live_connection": False
    }


def validate_and_sanitize(text: str, field_name: str) -> str:
    if not text:
        return text
    # Clean text to prevent SPL/command injection by only allowing alphanumeric, whitespace, and dashes
    sanitized = re.sub(r'[^\w\s\-]', '', text)
    if sanitized != text:
        raise HTTPException(
            status_code=400,
            detail=f"Security alert: Malicious characters detected in field '{field_name}'. Only alphanumeric, space, and dashes are allowed to prevent SPL/command injection."
        )
    return sanitized


@app.post("/api/v1/analyze", response_model=IncidentResponse)
@app.post("/api/v1/incident/analyze", response_model=IncidentResponse)
@limiter.limit("10/minute")
def analyze_incident_endpoint(request: Request, incident_request: IncidentRequest):
    """
    Submit an incident to the Executive Council.
    Runs the entire pipeline: Digital Twin sync -> Outlier scan -> MCP context enrichment -> Agent debate -> Consensus synthesis.
    """
    # Sanitize inputs to prevent SPL Injection
    user_sanitized = validate_and_sanitize(incident_request.user, "user")
    event_sanitized = validate_and_sanitize(incident_request.event, "event")
    severity_sanitized = validate_and_sanitize(incident_request.severity, "severity")
    
    try:
        incident = {
            "user": user_sanitized,
            "event": event_sanitized,
            "severity": severity_sanitized
        }
        # Execute workflow
        res = run_council(incident, verbose=False)
        
        stages = res.get("stages", {})
        return IncidentResponse(
            success=True,
            incident=incident,
            decision=stages.get("decision", {}),
            opinions=stages.get("opinions", []),
            debate=stages.get("debate", {}),
            simulation=stages.get("simulation", {}),
            twin=stages.get("twin", {})
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    # Look for cert files in api directory or root
    ssl_key = "api/key.pem"
    ssl_cert = "api/cert.pem"
    if os.path.exists(ssl_key) and os.path.exists(ssl_cert):
        print("Starting FastAPI with HTTPS/SSL enabled...")
        uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True, ssl_keyfile=ssl_key, ssl_certfile=ssl_cert)
    else:
        print("Starting FastAPI with HTTP (No SSL) on port 8001...")
        uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)

