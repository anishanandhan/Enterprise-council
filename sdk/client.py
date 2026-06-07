"""
sdk/client.py — Python Developer SDK for Enterprise Council AI

A developer-friendly client SDK to connect to the Enterprise Council AI API
or run the workflow locally.
"""

import requests
from typing import Dict, Any, Optional


class CouncilClient:
    """
    Client for interacting with the Enterprise Council AI Platform.
    
    Can run queries via the local REST API or locally in-process.
    """

    def __init__(self, api_url: str = "http://localhost:8001"):
        self.api_url = api_url.rstrip("/")

    def analyze_incident(self, user: str, event: str, severity: str = "Medium") -> Dict[str, Any]:
        """
        Send an incident to the Executive Council REST API for analysis and consensus.
        
        Args:
            user: Username or entity under investigation
            event: Event type (e.g., Privilege Escalation)
            severity: Severity level (Critical, High, Medium, Low)
            
        Returns:
            Dict containing the executive decision, agent stances, and impact simulation.
        """
        url = f"{self.api_url}/api/v1/incident/analyze"
        payload = {
            "user": user,
            "event": event,
            "severity": severity
        }
        
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            raise RuntimeError(f"API request failed with status {response.status_code}: {response.text}")
            
        return response.json()

    def check_health(self) -> Dict[str, Any]:
        """Check the API connection and Splunk status."""
        url = f"{self.api_url}/api/v1/health"
        response = requests.get(url)
        if response.status_code != 200:
            raise RuntimeError(f"Health check failed: {response.text}")
        return response.json()


# ── Local Run Helper (Alternative to API) ──────────────────────────

def analyze_local(user: str, event: str, severity: str = "Medium") -> Dict[str, Any]:
    """
    Run the analysis pipeline in-process (local fallback execution).
    Does not require the REST API server to be running.
    """
    from orchestrator.workflow import run_council
    incident = {
        "user": user,
        "event": event,
        "severity": severity
    }
    return run_council(incident, verbose=False)
