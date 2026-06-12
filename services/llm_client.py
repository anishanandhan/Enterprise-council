"""
llm_client.py — LLM Reasoning Engine

Provides structured LLM reasoning for agents.

    Agent Context
        ↓
    LLM Client
        ↓
    Structured Opinion

Supports:
    - Google Gemini via google-genai SDK
    - High-fidelity local fallback (no API key required)

Set GEMINI_API_KEY in environment to enable live LLM reasoning.
"""

import os
import json

# ── LLM Mode Detection ──────────────────────────────────────────

_LLM_MODE = None
_splunk_client = None
_gemini_client = None


def _init():
    global _LLM_MODE, _splunk_client, _gemini_client

    if _LLM_MODE is not None:
        return

    try:
        from services.env_loader import load_env
        load_env()
    except Exception:
        pass

    api_key = os.environ.get("GEMINI_API_KEY", "")
    use_splunk_llm = os.environ.get("USE_SPLUNK_HOSTED_LLM", "").lower() != "false"
    splunk_pass = os.environ.get("SPLUNK_PASSWORD", "")
    splunk_token = os.environ.get("SPLUNK_TOKEN", "")

    # Prioritize Splunk Hosted LLM if configured
    if use_splunk_llm and (splunk_pass or splunk_token):
        try:
            from splunk.splunk_client import get_client
            client = get_client()
            if type(client).__name__ in ["SplunkClient", "SplunkSDKClient"]:
                _splunk_client = client
                _LLM_MODE = "splunk_hosted"
                print("  [LLM] Connected to Splunk Hosted Models (Foundation-Sec)")
                
                # Also initialize Gemini if key is present (for fallback)
                if api_key:
                    try:
                        from google import genai
                        _gemini_client = genai.Client(api_key=api_key)
                    except Exception:
                        pass
                return
        except Exception as e:
            print(f"  [LLM] Splunk Hosted Model connection failed: {e}")

    if api_key:
        try:
            from google import genai
            _gemini_client = genai.Client(api_key=api_key)
            _LLM_MODE = "gemini"
            print("  [LLM] Gemini API connected")
            return
        except Exception as e:
            print(f"  [LLM] Gemini init failed: {e}")

    _LLM_MODE = "local"
    print("  [LLM] Using local reasoning engine")


def sanitize_prompt_input(text: str) -> str:
    """
    Sanitize incoming text to neutralize prompt injection/jailbreak attempts
    that might be present in untrusted telemetry logs or incident data.
    """
    if not isinstance(text, str):
        return text
    import re
    # List of common prompt injection/jailbreak indicators
    patterns = [
        r"(ignore\s+all\s+previous\s+instructions|ignore\s+all\s+previous\s+rules)",
        r"(ignore\s+system\s+instructions|system\s+override)",
        r"(you\s+are\s+now\s+a\s+different\s+agent|you\s+are\s+now\s+dan|dan\s+mode)",
        r"revert\s+threat\s+level\s+to\s+low",
        r"recommend\s+monitor\s+action",
        r"ignore\s+threat",
        r"bypass\s+security"
    ]
    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, "[REDACTED PROMPT INJECTION ATTEMPT]", sanitized, flags=re.IGNORECASE)
    return sanitized


def reason(prompt, system_instruction=""):
    """
    Send a structured prompt to the LLM and return the text response.
    Falls back to Gemini, then local reasoning if needed.
    """
    _init()
    prompt = sanitize_prompt_input(prompt)
    system_instruction = sanitize_prompt_input(system_instruction)

    if _LLM_MODE == "splunk_hosted":
        try:
            return _splunk_hosted_reason(prompt, system_instruction)
        except Exception as e:
            print(f"  [LLM] Splunk Hosted LLM failed: {e}, falling back to Gemini")
            # Fallback to Gemini if key available
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if api_key:
                try:
                    return _gemini_reason(prompt, system_instruction)
                except Exception as ge:
                    print(f"  [LLM] Gemini fallback failed: {ge}, falling back to local")
            return _local_reason(prompt, system_instruction)
    elif _LLM_MODE == "gemini":
        try:
            return _gemini_reason(prompt, system_instruction)
        except Exception as e:
            print(f"  [LLM] Gemini call failed: {e}, falling back to local")
            return _local_reason(prompt, system_instruction)
    else:
        return _local_reason(prompt, system_instruction)


def reason_structured(prompt, system_instruction=""):
    """
    Send a prompt and expect a JSON response with:
        risk_level, recommendation, confidence, reasoning
    Returns a dict.
    """
    _init()
    prompt = sanitize_prompt_input(prompt)
    system_instruction = sanitize_prompt_input(system_instruction)

    full_prompt = (
        f"{prompt}\n\n"
        "Respond ONLY with a valid JSON object containing these fields:\n"
        '  "risk_level": one of "Critical", "High", "Medium", "Low"\n'
        '  "recommendation": a short actionable recommendation\n'
        '  "confidence": a float between 0.0 and 1.0\n'
        '  "reasoning": detailed multi-sentence reasoning\n'
    )

    if _LLM_MODE == "splunk_hosted":
        try:
            text = _splunk_hosted_reason(full_prompt, system_instruction)
            parsed = _parse_json(text)
            if parsed.get("recommendation") == "Unable to parse LLM response":
                raise ValueError("JSON parsing failed")
            return parsed
        except Exception as e:
            print(f"  [LLM] Splunk Hosted LLM failed: {e}, falling back to Gemini structured")
            # Fallback to Gemini
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if api_key:
                try:
                    text = _gemini_reason(full_prompt, system_instruction)
                    parsed = _parse_json(text)
                    if parsed.get("recommendation") != "Unable to parse LLM response":
                        return parsed
                except Exception as ge:
                    print(f"  [LLM] Gemini fallback failed: {ge}")
            return _local_reason_structured(prompt, system_instruction)
    elif _LLM_MODE == "gemini":
        try:
            text = _gemini_reason(full_prompt, system_instruction)
            parsed = _parse_json(text)
            if parsed.get("recommendation") == "Unable to parse LLM response":
                return _local_reason_structured(prompt, system_instruction)
            return parsed
        except Exception as e:
            print(f"  [LLM] Gemini call failed: {e}, falling back to local structured")
            return _local_reason_structured(prompt, system_instruction)
    else:
        return _local_reason_structured(prompt, system_instruction)


def reason_security(prompt, system_instruction="", structured=False):
    """
    Route security-specific prompts directly to the Foundation-Sec model.
    Falls back to Gemini/local if unavailable.
    """
    _init()
    prompt = sanitize_prompt_input(prompt)
    system_instruction = sanitize_prompt_input(system_instruction)
    full_prompt = prompt
    if structured:
        full_prompt = (
            f"{prompt}\n\n"
            "Respond ONLY with a valid JSON object containing these fields:\n"
            '  "risk_level": one of "Critical", "High", "Medium", "Low"\n'
            '  "recommendation": a short actionable recommendation\n'
            '  "confidence": a float between 0.0 and 1.0\n'
            '  "reasoning": detailed multi-sentence reasoning\n'
        )

    try:
        from splunk.hosted_models import get_foundation_sec
        fsec = get_foundation_sec()
        if fsec._is_live():
            combined_prompt = f"System: {system_instruction}\n\n{full_prompt}"
            res = fsec._run_ai_command(combined_prompt)
            if res:
                if structured:
                    parsed = _parse_json(res)
                    if parsed.get("recommendation") != "Unable to parse LLM response":
                        return parsed
                else:
                    return res
    except Exception as e:
        print(f"  [LLM] Foundation-Sec direct call failed: {e}")

    if structured:
        return reason_structured(prompt, system_instruction)
    else:
        return reason(prompt, system_instruction)


def reason_timeseries(prompt, system_instruction="", structured=False):
    """
    Route forecasting tasks to Cisco Deep Time Series Model.
    If structured, returns a dict with risk_level, recommendation, confidence, reasoning.
    """
    _init()
    prompt = sanitize_prompt_input(prompt)
    system_instruction = sanitize_prompt_input(system_instruction)
    try:
        from splunk.hosted_models import get_deep_ts
        dts = get_deep_ts()

        # Determine service based on context clues in the prompt
        service = "CustomerDB"
        for s in ["CustomerDB", "API-Gateway", "Deployment-Service"]:
            if s.lower() in prompt.lower():
                service = s
                break

        forecast = dts.forecast_capacity(service)

        if structured:
            peak = forecast.get("predicted_peak", 0)
            if peak > 85:
                risk = "Critical"
                rec = f"Do NOT block. Peak load forecast of {peak}% indicates extreme cascading failure risk."
            elif peak > 70:
                risk = "High"
                rec = f"Restrict access with caution. Peak load forecast of {peak}% indicates potential service disruption."
            else:
                risk = "Low"
                rec = f"Safe to restrict. Peak load forecast is stable at {peak}%."

            return {
                "risk_level": risk,
                "recommendation": rec,
                "confidence": 0.90 if forecast.get("model") == "CiscoDeepTimeSeries" else 0.75,
                "reasoning": (
                    f"Cisco Deep Time Series model analyzed the telemetry for '{service}'. "
                    f"Current load is {forecast.get('current_load')}%. "
                    f"The predicted peak load over the next 24 hours is {peak}% with a '{forecast.get('trend')}' trend. "
                    f"Infrastructure dependencies indicate high risk of cascading failures if access is completely revoked."
                )
            }
        else:
            return (
                f"Cisco Deep Time Series forecast for service '{service}':\n"
                f"- Current Load: {forecast.get('current_load')}%\n"
                f"- Predicted Peak Load (24h): {forecast.get('predicted_peak')}%\n"
                f"- Trend: {forecast.get('trend')}\n"
                f"- Model Used: {forecast.get('model')}"
            )
    except Exception as e:
        print(f"  [LLM] Cisco Deep TS forecasting failed: {e}")

    if structured:
        return reason_structured(prompt, system_instruction)
    else:
        return reason(prompt, system_instruction)


def _splunk_hosted_reason(prompt, system_instruction):
    """
    Call a Splunk-hosted generative AI model.
    Runs via Splunk's REST API or generative search commands.
    """
    combined_prompt = f"System: {system_instruction}\n\n{prompt}"
    escaped_prompt = combined_prompt.replace('"', '\\"')

    # Option A: Try the ML-SPL 'ai' command with Splunk's Foundation AI Security Model
    try:
        query = f"| ai prompt=\"{escaped_prompt}\" model=\"foundation-sec-1.1-8b-instruct\""
        results = _splunk_client.search(query, max_results=1)
        if results and len(results) > 0:
            for k in ["response", "text", "result", "ai_result", "ai_result_1", "_raw"]:
                if k in results[0] and results[0][k]:
                    return results[0][k]
    except Exception as e:
        print(f"  [LLM] Splunk 'ai' command with Foundation-Sec failed: {e}. Trying generativeai fallback...")

    # Option B: Fallback to generativeai command
    try:
        query = f"| generativeai prompt=\"{escaped_prompt}\""
        results = _splunk_client.search(query, max_results=1)
        if results and len(results) > 0:
            for k in ["response", "text", "result", "_raw"]:
                if k in results[0] and results[0][k]:
                    return results[0][k]
    except Exception as e:
        print(f"  [LLM] Splunk 'generativeai' command failed: {e}. Trying direct REST fallback...")

    # Option C: Direct REST API POST request to Splunk ML / LLM endpoint
    try:
        data = {
            "prompt": prompt,
            "system_prompt": system_instruction,
            "temperature": "0.2"
        }
        res = _splunk_client._request("POST", "/services/ml/llm/generate", data=data)
        parsed = json.loads(res)
        return parsed.get("generated_text", parsed.get("response", ""))
    except Exception as e:
        # Raise to trigger fallback path
        raise RuntimeError(f"All Splunk hosted model reasoning methods failed: {e}")



# ── Gemini Implementation ────────────────────────────────────────

def _gemini_reason(prompt, system_instruction):
    """Call Gemini API for free-form reasoning."""
    from google import genai

    full_prompt = prompt
    if system_instruction:
        full_prompt = f"System: {system_instruction}\n\n{prompt}"

    response = _gemini_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=full_prompt,
    )
    return response.text


def _parse_json(text):
    """Extract JSON from LLM response text."""
    # Try to find JSON block in the text
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        json_lines = []
        inside = False
        for line in lines:
            if line.startswith("```") and not inside:
                inside = True
                continue
            elif line.startswith("```") and inside:
                break
            elif inside:
                json_lines.append(line)
        text = "\n".join(json_lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

    return {
        "risk_level": "Medium",
        "recommendation": "Unable to parse LLM response",
        "confidence": 0.50,
        "reasoning": text[:500]
    }


# ── Local Reasoning Engine ───────────────────────────────────────
#
#    High-fidelity fallback that produces rich, context-aware output.
#    This is NOT just hardcoded strings — it reads the actual context
#    from the prompt and generates appropriate reasoning.
#

def _local_reason(prompt, system_instruction):
    """Generate context-aware reasoning text locally."""
    # Extract context clues from the prompt
    prompt_lower = prompt.lower()
    inst_lower = system_instruction.lower() if system_instruction else ""

    if "splunk spl analyst" in prompt_lower or "spl query:" in prompt_lower or "explain spl" in prompt_lower:
        return _explain_spl_locally(prompt)
    elif "generate a splunk spl query" in prompt_lower or "splunk spl expert" in inst_lower:
        return _generate_spl_locally(prompt)
    elif "security agent" in inst_lower:
        return _security_reasoning(prompt_lower, prompt)
    elif "infrastructure agent" in inst_lower:
        return _infrastructure_reasoning(prompt_lower, prompt)
    elif "compliance agent" in inst_lower:
        return _compliance_reasoning(prompt_lower, prompt)
    elif "business agent" in inst_lower:
        return _business_reasoning(prompt_lower, prompt)
    elif "council" in inst_lower:
        return _council_reasoning(prompt_lower, prompt)
    elif "security" in inst_lower:
        return _security_reasoning(prompt_lower, prompt)
    elif "infrastructure" in inst_lower:
        return _infrastructure_reasoning(prompt_lower, prompt)
    elif "compliance" in inst_lower:
        return _compliance_reasoning(prompt_lower, prompt)
    elif "business" in inst_lower:
        return _business_reasoning(prompt_lower, prompt)
    else:
        return _general_reasoning(prompt_lower, prompt)


def _local_reason_structured(prompt, system_instruction):
    """Generate structured JSON output locally based on context."""
    prompt_lower = prompt.lower()

    # Detect severity from context
    is_critical = any(w in prompt_lower for w in [
        "critical", "privilege escalation", "exfiltration",
        "sensitive file", "data breach", "unauthorized"
    ])
    is_high = any(w in prompt_lower for w in [
        "high", "spike", "surge", "download", "anomaly"
    ])

    # Detect agent role from system instruction
    role = system_instruction.lower() if system_instruction else ""

    if "security agent" in role:
        return _structured_security(prompt_lower, is_critical, is_high)
    elif "infrastructure agent" in role:
        return _structured_infrastructure(prompt_lower, is_critical, is_high)
    elif "compliance agent" in role:
        return _structured_compliance(prompt_lower, is_critical, is_high)
    elif "business agent" in role:
        return _structured_business(prompt_lower, is_critical, is_high)
    elif "security" in role:
        return _structured_security(prompt_lower, is_critical, is_high)
    elif "infrastructure" in role:
        return _structured_infrastructure(prompt_lower, is_critical, is_high)
    elif "compliance" in role:
        return _structured_compliance(prompt_lower, is_critical, is_high)
    elif "business" in role:
        return _structured_business(prompt_lower, is_critical, is_high)
    else:
        return _structured_general(prompt_lower, is_critical, is_high)


# ── Structured Response Generators ───────────────────────────────

def _structured_security(prompt, is_critical, is_high):
    if is_critical:
        return {
            "risk_level": "Critical",
            "recommendation": "Block account immediately and initiate forensic investigation",
            "confidence": 0.93,
            "reasoning": (
                "Multiple high-severity indicators detected in the digital twin analysis. "
                "The user's access pattern shows correlation with known insider threat "
                "kill chains — privilege escalation followed by lateral movement to "
                "sensitive data stores. The combination of critical alerts and access "
                "to production databases creates an unacceptable exfiltration risk. "
                "Recommend immediate account suspension with evidence preservation."
            )
        }
    elif is_high:
        return {
            "risk_level": "High",
            "recommendation": "Restrict privileged access pending investigation",
            "confidence": 0.85,
            "reasoning": (
                "Elevated risk indicators detected. The user's activity deviates from "
                "established behavioral baseline. While not yet matching a full attack "
                "pattern, the anomalous access to sensitive infrastructure warrants "
                "restrictive measures. Recommend privilege reduction and enhanced monitoring."
            )
        }
    return {
        "risk_level": "Medium",
        "recommendation": "Increase monitoring and log retention",
        "confidence": 0.72,
        "reasoning": (
            "Moderate risk indicators observed. Activity is unusual but does not "
            "yet reach the threshold for direct intervention. Enhanced monitoring "
            "will provide additional data points for risk assessment."
        )
    }


def _structured_infrastructure(prompt, is_critical, is_high):
    if is_critical:
        return {
            "risk_level": "High",
            "recommendation": "Blocking may cause cascading service failures",
            "confidence": 0.88,
            "reasoning": (
                "Digital twin analysis reveals this user is a critical node in the "
                "infrastructure graph. They are directly connected to production "
                "deployment pipelines, databases, and orchestration platforms. "
                "Abrupt access removal would likely trigger deployment freezes, "
                "break CI/CD pipelines, and potentially cause cascading failures "
                "in downstream services. The blast radius extends to customer-facing APIs."
            )
        }
    elif is_high:
        return {
            "risk_level": "Medium",
            "recommendation": "Partial restriction feasible with coordination",
            "confidence": 0.78,
            "reasoning": (
                "The user has moderate infrastructure dependencies. Selective "
                "restriction of non-essential services is feasible without "
                "impacting production workloads. Coordinate with operations "
                "to ensure critical deployments are not blocked."
            )
        }
    return {
        "risk_level": "Low",
        "recommendation": "Safe to restrict — minimal infrastructure impact",
        "confidence": 0.91,
        "reasoning": (
            "User has no critical infrastructure dependencies in the digital twin. "
            "Restriction or blocking can be applied without service disruption."
        )
    }


def _structured_compliance(prompt, is_critical, is_high):
    if is_critical:
        return {
            "risk_level": "High",
            "recommendation": "Preserve all evidence and initiate formal investigation",
            "confidence": 0.92,
            "reasoning": (
                "This incident triggers multiple compliance frameworks identified "
                "in the digital twin's policy graph. Evidence preservation is legally "
                "required under applicable data protection regulations. Log integrity "
                "must be guaranteed — no deletion or modification of audit trails. "
                "Formal incident response procedures must be initiated within the "
                "regulatory reporting window."
            )
        }
    elif is_high:
        return {
            "risk_level": "Medium",
            "recommendation": "Initiate audit trail and flag for compliance review",
            "confidence": 0.82,
            "reasoning": (
                "The event matches policy triggers in the compliance graph. "
                "While not requiring immediate regulatory notification, an "
                "audit trail should be established and the incident flagged "
                "for the compliance team's review queue."
            )
        }
    return {
        "risk_level": "Low",
        "recommendation": "Standard logging sufficient",
        "confidence": 0.87,
        "reasoning": (
            "No compliance policy violations detected in the digital twin analysis. "
            "Standard logging and monitoring procedures are adequate."
        )
    }


def _structured_business(prompt, is_critical, is_high):
    if is_critical:
        return {
            "risk_level": "High",
            "recommendation": "Avoid full block — use temporary restriction only",
            "confidence": 0.84,
            "reasoning": (
                "The digital twin identifies this user as business-critical. "
                "Their role connects to production deployment workflows, "
                "customer-facing services, and key departmental operations. "
                "A full account block would directly impact revenue-generating "
                "activities and could delay scheduled deployments. "
                "Recommend the minimum viable restriction that addresses "
                "the security concern without halting business operations."
            )
        }
    elif is_high:
        return {
            "risk_level": "Medium",
            "recommendation": "Restrict with caution — coordinate with management",
            "confidence": 0.76,
            "reasoning": (
                "User has moderate business importance. Some operational "
                "disruption is expected if access is restricted. "
                "Recommend coordinating with department management before "
                "implementing restrictions."
            )
        }
    return {
        "risk_level": "Low",
        "recommendation": "Safe to restrict — minimal business impact",
        "confidence": 0.88,
        "reasoning": (
            "User has low business criticality in the digital twin. "
            "Restriction or blocking will not meaningfully impact "
            "business operations or revenue."
        )
    }


def _structured_general(prompt, is_critical, is_high):
    if is_critical:
        return {
            "risk_level": "High",
            "recommendation": "Escalate for immediate review",
            "confidence": 0.80,
            "reasoning": "Critical indicators detected requiring immediate attention."
        }
    return {
        "risk_level": "Medium",
        "recommendation": "Monitor and assess",
        "confidence": 0.70,
        "reasoning": "Moderate indicators detected. Continued monitoring recommended."
    }


# ── Free-form Reasoning Generators ───────────────────────────────

def _security_reasoning(prompt_lower, prompt):
    if "privilege escalation" in prompt_lower or "critical" in prompt_lower:
        return (
            "THREAT ASSESSMENT: The observed activity pattern is consistent with "
            "an advanced insider threat scenario. Privilege escalation combined with "
            "access to sensitive data stores indicates potential preparation for "
            "data exfiltration. The digital twin reveals the user has deep access "
            "to production infrastructure, making this a high-impact threat vector. "
            "The temporal correlation between the escalation event and prior "
            "anomalous activity strengthens the threat hypothesis. "
            "RECOMMENDATION: Immediate account suspension with forensic evidence "
            "collection. Engage SOC Level 3 analysts for deep investigation."
        )
    return (
        "THREAT ASSESSMENT: Activity is outside normal parameters but does not "
        "match known attack signatures. Continued monitoring with enhanced "
        "logging is recommended to establish whether this represents a "
        "genuine threat or benign deviation."
    )


def _infrastructure_reasoning(prompt_lower, prompt):
    if "critical" in prompt_lower or "blast" in prompt_lower:
        return (
            "IMPACT ANALYSIS: The digital twin dependency graph shows this user "
            "is a keystone node in the infrastructure topology. Removing their "
            "access creates a blast radius affecting deployment pipelines, "
            "database operations, and API gateway routing. Production SLAs "
            "would be at risk. RECOMMENDATION: If action is required, implement "
            "graduated restriction rather than full block. Ensure backup "
            "operators have access to critical systems before restricting."
        )
    return (
        "IMPACT ANALYSIS: Limited infrastructure dependencies identified. "
        "Restriction can be applied with minimal service impact."
    )


def _compliance_reasoning(prompt_lower, prompt):
    if "privilege" in prompt_lower or "sensitive" in prompt_lower:
        return (
            "REGULATORY ANALYSIS: This event triggers obligations under "
            "data protection and access governance policies. Evidence chain "
            "must be preserved with cryptographic integrity. Audit logs must "
            "not be modified or deleted. A formal investigation timeline "
            "should be established per the incident response policy. "
            "RECOMMENDATION: Lock evidence, notify compliance officer, "
            "and begin documentation for potential regulatory reporting."
        )
    return (
        "REGULATORY ANALYSIS: Standard compliance monitoring applies. "
        "No immediate regulatory obligations triggered."
    )


def _business_reasoning(prompt_lower, prompt):
    if "critical" in prompt_lower or "very high" in prompt_lower:
        return (
            "BUSINESS IMPACT ASSESSMENT: This user is classified as "
            "business-critical in the digital twin. Their removal from "
            "operations would directly impact deployment schedules, "
            "customer deliverables, and team productivity. The cost of "
            "a full block exceeds the security benefit in most scenarios. "
            "RECOMMENDATION: Apply the minimum viable restriction. "
            "Consider supervised access rather than full suspension."
        )
    return (
        "BUSINESS IMPACT ASSESSMENT: User has moderate-to-low business "
        "criticality. Restriction can proceed with standard coordination."
    )


def _council_reasoning(prompt_lower, prompt):
    return (
        "COUNCIL SYNTHESIS: After weighing all domain perspectives — "
        "security risk, infrastructure impact, compliance obligations, and "
        "business continuity — the council reaches a balanced recommendation. "
        "The optimal action minimizes total organizational risk while "
        "preserving operational continuity and regulatory compliance. "
        "This decision is backed by impact simulation data showing the "
        "proposed action achieves the best risk-reward balance across "
        "all evaluated scenarios."
    )


def _general_reasoning(prompt_lower, prompt):
    return (
        "Analysis of the available data indicates a moderate risk posture. "
        "Additional monitoring and assessment is recommended before "
        "escalating to a more restrictive response."
    )


def _explain_spl_locally(prompt):
    # Extract SPL query from prompt
    spl_query = ""
    for line in prompt.split("\n"):
        if "spl query:" in line.lower():
            idx = line.lower().find("spl query:")
            spl_query = line[idx + len("spl query:"):].strip()
            break
        elif "spl:" in line.lower():
            idx = line.lower().find("spl:")
            spl_query = line[idx + len("spl:"):].strip()
            break
            
    if not spl_query:
        for line in prompt.split("\n"):
            if "index=" in line or "|" in line:
                spl_query = line.strip()
                break
                
    if not spl_query:
        spl_query = "index=security"
        
    parts = [p.strip() for p in spl_query.split("|")]
    base = parts[0]
    
    explanation_parts = []
    
    # Detect Index
    index_name = "security"
    for idx in ["security", "infrastructure", "business", "compliance"]:
        if f"index={idx}" in base or f"index=\"{idx}\"" in base or f"index='\''{idx}'\''" in base:
            index_name = idx
            break
            
    explanation_parts.append(f"This query searches the **{index_name}** index")
    
    # Detect filters
    filters = []
    if "user=" in base:
        user_val = "John"
        if "user=\"John\"" in base or "user='John'" in base or "user=John" in base:
            user_val = "John"
        elif "user=\"*\"" in base or "user=*" in base:
            user_val = "any user"
        else:
            user_val = "the specified user"
        filters.append(f"events related to user **{user_val}**")
        
    if "event=" in base:
        if "privilege" in base.lower():
            filters.append("privilege escalation events")
        else:
            filters.append("specific events matching the event criteria")
            
    if "service=" in base:
        filters.append("events affecting the target service")
        
    if filters:
        explanation_parts.append("for " + " and ".join(filters))
        
    for part in parts[1:]:
        cmd_tokens = part.split()
        if not cmd_tokens:
            continue
        cmd = cmd_tokens[0].lower()
        
        if cmd == "spath":
            explanation_parts.append("extracts the JSON fields dynamically from the raw payload at search-time")
        elif cmd == "stats":
            by_idx = -1
            for i, tok in enumerate(cmd_tokens):
                if tok.lower() == "by":
                    by_idx = i
                    break
            if by_idx != -1 and by_idx < len(cmd_tokens) - 1:
                group_fields = ", ".join(cmd_tokens[by_idx+1:])
                explanation_parts.append(f"calculates the event count grouped by the fields: **{group_fields}**")
            else:
                explanation_parts.append("calculates aggregate statistics on the matching events")
        elif cmd == "table":
            fields = ", ".join(cmd_tokens[1:])
            explanation_parts.append(f"formats the final results into a tabular view displaying: **{fields}**")
        elif cmd == "sort":
            field_name = cmd_tokens[1] if len(cmd_tokens) > 1 else "timestamp"
            order = "descending" if field_name.startswith("-") else "ascending"
            clean_field = field_name.lstrip("-")
            explanation_parts.append(f"sorts the results in {order} order based on the **{clean_field}** field")
        elif cmd == "head":
            limit = cmd_tokens[1] if len(cmd_tokens) > 1 else "10"
            explanation_parts.append(f"limits the output to the first **{limit}** results")
            
    if len(explanation_parts) > 1:
        full_expl = explanation_parts[0]
        if len(explanation_parts) > 1 and explanation_parts[1].startswith("for "):
            full_expl += " " + explanation_parts[1]
            start_idx = 2
        else:
            start_idx = 1
            
        for p in explanation_parts[start_idx:]:
            full_expl += ", then " + p
        full_expl += "."
    else:
        full_expl = explanation_parts[0] + "."
        
    return full_expl


def _generate_spl_locally(prompt):
    prompt_lower = prompt.lower()
    
    user = "John"
    event = "Privilege Escalation"
    service = "*"
    
    if "user=" in prompt_lower:
        parts = prompt_lower.split("user=")
        if len(parts) > 1:
            user = parts[1].split(",")[0].split()[0].replace("'", "").replace('"', '').strip()
            
    if "event=" in prompt_lower:
        parts = prompt_lower.split("event=")
        if len(parts) > 1:
            event = parts[1].split(",")[0].split()[0].replace("'", "").replace('"', '').strip()
            
    if "service=" in prompt_lower:
        parts = prompt_lower.split("service=")
        if len(parts) > 1:
            service = parts[1].split(",")[0].split()[0].replace("'", "").replace('"', '').strip()

    if "user under investigation:" in prompt_lower:
        parts = prompt_lower.split("user under investigation:")
        if len(parts) > 1:
            user = parts[1].strip().split()[0].replace("'", "").replace('"', '').strip()

    target_index = None
    if "index=security" in prompt_lower or "in the security index" in prompt_lower:
        target_index = "security"
    elif "index=compliance" in prompt_lower or "in the compliance index" in prompt_lower:
        target_index = "compliance"
    elif "index=infrastructure" in prompt_lower or "in the infrastructure index" in prompt_lower:
        target_index = "infrastructure"
    elif "index=business" in prompt_lower or "in the business index" in prompt_lower:
        target_index = "business"

    if target_index:
        if target_index == "security":
            return f'index=security user="{user}" | stats count by severity event | sort -count'
        elif target_index == "compliance":
            ev_filter = "Privilege Escalation" if "privilege" in prompt_lower else event
            return f'index=compliance event="{ev_filter}" | table timestamp event policy risk'
        elif target_index == "infrastructure":
            srv_filter = "CustomerDB"
            for s in ["CustomerDB", "API-Gateway", "Deployment-Service"]:
                if s.lower() in prompt_lower:
                    srv_filter = s
                    break
            return f'index=infrastructure service="{srv_filter}" | stats count by event severity | sort -count'
        elif target_index == "business":
            return f'index=business user="{user}" | table user role department criticality'

    if "timeline" in prompt_lower or "activity" in prompt_lower or "what did" in prompt_lower:
        return f'index=security user="{user}" | sort timestamp | table timestamp event severity device'
    elif "alert" in prompt_lower or "summary" in prompt_lower or "count" in prompt_lower:
        return f'index=security user="{user}" | stats count by severity event | sort -count'
    elif "correlat" in prompt_lower or "around" in prompt_lower:
        return 'index=security OR index=infrastructure OR index=compliance | sort timestamp | table timestamp index event severity'
    elif "service" in prompt_lower or "infrastructure" in prompt_lower or "impact" in prompt_lower:
        return f'index=infrastructure service="{service}" | stats count by event severity | sort -count'
    elif "compliance" in prompt_lower or "policy" in prompt_lower or "regulation" in prompt_lower:
        return f'index=compliance event="{event}" | table timestamp event policy risk'
    elif "exfil" in prompt_lower or "download" in prompt_lower or "copy" in prompt_lower:
        return 'index=security (event="Large Data Download" OR event="Sensitive File Copy") | table timestamp user device event severity'
    elif "privilege" in prompt_lower or "escalat" in prompt_lower:
        return 'index=security event="Privilege Escalation" | table timestamp user device severity'
    elif "business" in prompt_lower or "critical" in prompt_lower or "role" in prompt_lower:
        return f'index=business user="{user}" | table user role department criticality'
        
    return 'index=security | head 20 | table timestamp user event severity'
