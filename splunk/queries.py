"""
queries.py — Centralized SPL Queries

All Splunk search queries live here.
Agents and services reference these instead of writing inline SPL.
"""

SECURITY_EVENTS = "index=security"
INFRA_EVENTS = "index=infrastructure"
BUSINESS_EVENTS = "index=business"
COMPLIANCE_EVENTS = "index=compliance"

# Targeted queries for specific investigations
USER_HISTORY = "index=security user={user}"
SERVICE_HEALTH = "index=infrastructure service={service}"
USER_COMPLIANCE = "index=compliance"
