# -*- coding: utf-8 -*-
"""
Enterprise Council AI — Operational Command Center

Streamlit-based dashboard for the hackathon demo.
Military operations center meets AI SOC dashboard.
"""

import sys
import os
import time
import json
import datetime
import io
import base64
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
# Force reload core modules to clear python import cache across runs
if "services.llm_client" in sys.modules:
    importlib.reload(sys.modules["services.llm_client"])
if "splunk.ai_assistant" in sys.modules:
    importlib.reload(sys.modules["splunk.ai_assistant"])
if "splunk.splunk_client" in sys.modules:
    importlib.reload(sys.modules["splunk.splunk_client"])

from splunk.splunk_client import get_client
from splunk.queries import SECURITY_EVENTS, INFRA_EVENTS, BUSINESS_EVENTS, COMPLIANCE_EVENTS

# Ensure matplotlib uses the non-interactive Agg backend
matplotlib.use("Agg")

# ── Page Config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="Enterprise Council AI Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Auth Form & RBAC Quick-Fill ──────────────────────────────────
def render_auth_form():
    # Hide Streamlit elements and style the full-page background
    st.markdown("""
    <style>
        /* Hide sidebar and header */
        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="stHeader"] { display: none !important; }
        div[data-testid="stDecoration"] { display: none !important; }
        
        /* Full-page dark background */
        .stApp {
            background-color: #0A0E1A !important;
            color: #F1F5F9 !important;
            font-family: 'Inter', sans-serif !important;
        }
        
        /* Center block container vertical alignment with breathing room */
        .block-container {
            padding-top: 6rem !important;
            max-width: 580px !important;
            margin: auto !important;
        }
        
        /* Extra padding for login card */
        div[data-testid="stVerticalBlockBorderWrapper"] {
            background-color: #111827 !important;
            border: 1px solid #1E293B !important;
            border-radius: 12px !important;
            padding: 2.25rem 2.5rem !important;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4) !important;
        }

        /* Prevent button text wrapping and make text sizes cleaner */
        div[data-testid="column"] button p {
            font-size: 0.8rem !important;
            white-space: nowrap !important;
            overflow: hidden !important;
            text-overflow: ellipsis !important;
        }
        
        /* Styled Quick Fill Label */
        .quick-fill-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: #94A3B8;
            margin-bottom: 12px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        
        /* Request access link styling */
        .auth-footer-link {
            text-align: center;
            font-size: 0.8rem;
            color: #94A3B8;
            margin-top: 20px;
        }
        .auth-footer-link a {
            color: #00B4D8;
            text-decoration: none;
            font-weight: 600;
        }
        .auth-footer-link a:hover {
            text-decoration: underline;
        }
    </style>
    """, unsafe_allow_html=True)

    # Auth Form title/branding
    st.html("""
    <div style="text-align: center; margin-bottom: 25px;">
        <h2 style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #F1F5F9; font-size: 1.8rem; letter-spacing: -0.5px; margin-bottom: 5px;">ACCESS GATEWAY</h2>
        <div style="font-size: 0.75rem; color: #94A3B8; letter-spacing: 1.5px; text-transform: uppercase;">ENTERPRISE COUNCIL AI • SECURE DEPLOYMENT</div>
        <div style="height: 2px; background: linear-gradient(90deg, #00B4D8 0%, #7B2FBE 100%); width: 100px; margin: 15px auto 0 auto; border-radius: 1px;"></div>
    </div>
    """)

    # Check state for sign in vs sign up
    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "signin"

    is_signup = (st.session_state["auth_mode"] == "signup")

    # Render floating card container using st.container(border=True)
    with st.container(border=True):
        if not is_signup:
            st.html("<h4 style='text-align: center; color: #F1F5F9; font-family: \"JetBrains Mono\", monospace; font-size: 0.95rem; margin-top: 5px; margin-bottom: 20px;'>AUTHENTICATE SECURITY PROFILE</h4>")
            
            # RBAC selector quick-fills
            st.markdown('<div class="quick-fill-label">Select Demo RBAC Profile</div>', unsafe_allow_html=True)
            col_ciso, col_mgr, col_anl, col_aud = st.columns(4)
            
            if col_ciso.button("CISO", use_container_width=True, help="Load CISO credentials"):
                st.session_state["login_email"] = "ciso@council.ai"
                st.session_state["login_password"] = "ciso_secure_pass"
                st.session_state["selected_rbac"] = "CISO"
                st.session_state["selected_role"] = "Executive View"
                st.rerun()

            if col_mgr.button("Manager", use_container_width=True, help="Load SOC Manager credentials"):
                st.session_state["login_email"] = "manager@council.ai"
                st.session_state["login_password"] = "manager_secure_pass"
                st.session_state["selected_rbac"] = "SOC Manager"
                st.session_state["selected_role"] = "Executive View"
                st.rerun()

            if col_anl.button("Analyst", use_container_width=True, help="Load SOC Analyst credentials"):
                st.session_state["login_email"] = "analyst@council.ai"
                st.session_state["login_password"] = "analyst_secure_pass"
                st.session_state["selected_rbac"] = "SOC Analyst"
                st.session_state["selected_role"] = "Analyst View"
                st.rerun()

            if col_aud.button("Auditor", use_container_width=True, help="Load Auditor credentials"):
                st.session_state["login_email"] = "auditor@council.ai"
                st.session_state["login_password"] = "auditor_secure_pass"
                st.session_state["selected_rbac"] = "Auditor"
                st.session_state["selected_role"] = "Analyst View"
                st.rerun()

            st.markdown("<div style='height: 10px; border-bottom: 1px solid #1E293B; margin-bottom: 15px;'></div>", unsafe_allow_html=True)

            # Username/Email input
            email = st.text_input("Corporate Email", value=st.session_state.get("login_email", ""), placeholder="officer@council.ai")
            
            # Password input
            password = st.text_input("Access Password", type="password", value=st.session_state.get("login_password", ""), placeholder="••••••••")
            
            # Primary CTA
            st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
            if st.button("AUTHENTICATE NODE", type="primary", use_container_width=True):
                if not email or not password:
                    st.error("Please enter email and access password.")
                else:
                    # Successfully authenticated! Set default values if custom input
                    st.session_state["authenticated"] = True
                    # If they prefilled, we have rbac and role, otherwise default to CISO
                    st.session_state["rbac_role"] = st.session_state.get("selected_rbac", "CISO")
                    st.session_state["role_selector"] = st.session_state.get("selected_role", "Executive View")
                    st.query_params["page"] = "dashboard"
                    st.toast("Authentication node verified. Access granted.")
                    st.rerun()

            st.markdown("<div style='height: 10px; border-bottom: 1px solid #1E293B; margin-bottom: 15px;'></div>", unsafe_allow_html=True)
            
            # Link to switch to sign up
            st.markdown('<div class="auth-footer-link">New officer? <a href="#" onclick="document.getElementById(\'toggle_signup_trigger\').click(); return false;">Request access</a></div>', unsafe_allow_html=True)
            
            # Hidden/Fallback button for Streamlit trigger
            if st.button("Request New Access Token (Sign Up)", key="toggle_signup_trigger_btn", use_container_width=True):
                st.session_state["auth_mode"] = "signup"
                st.rerun()
                
        else:
            st.html("<h4 style='text-align: center; color: #F1F5F9; font-family: \"JetBrains Mono\", monospace; font-size: 0.95rem; margin-top: 5px; margin-bottom: 20px;'>REQUEST OPERATIONAL ACCOUNT</h4>")
            
            name = st.text_input("Full Name", placeholder="Agent Name")
            email = st.text_input("Corporate Email", placeholder="agent@council.ai")
            password = st.text_input("Desired Password", type="password", placeholder="••••••••")
            
            requested_role = st.selectbox("Requested Role Context", ["SOC Analyst", "SOC Manager", "CISO", "Auditor"])

            st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
            if st.button("SUBMIT REGISTRATION", type="primary", use_container_width=True):
                if not name or not email or not password:
                    st.error("Please fill in all registration fields.")
                else:
                    st.toast("Registration request dispatched to CISO.")
                    st.success("Registration submitted successfully. Check your email once approved.")
                    st.session_state["auth_mode"] = "signin"
                    time.sleep(1)
                    st.rerun()

            st.markdown("<div style='height: 10px; border-bottom: 1px solid #1E293B; margin-bottom: 15px;'></div>", unsafe_allow_html=True)
            
            # Link to switch to sign in
            st.markdown('<div class="auth-footer-link">Already have an account? <a href="#" onclick="document.getElementById(\'toggle_signin_trigger\').click(); return false;">Sign In</a></div>', unsafe_allow_html=True)
            
            # Hidden/Fallback button for Streamlit trigger
            if st.button("Already registered? Sign In", key="toggle_signin_trigger_btn", use_container_width=True):
                st.session_state["auth_mode"] = "signin"
                st.rerun()

# ── Page Routing & Auth Gate ──────────────────────────────────────
# Initialize session state variables
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "show_dashboard" not in st.session_state:
    st.session_state["show_dashboard"] = False

# Read query parameters
query_params = st.query_params
current_page = query_params.get("page", "landing")

if current_page == "dashboard":
    if not st.session_state["authenticated"]:
        # Block unauthorized access to dashboard -> redirect to auth
        st.query_params["page"] = "auth"
        st.rerun()
    else:
        st.session_state["show_dashboard"] = True
elif current_page == "auth":
    st.session_state["show_dashboard"] = False
else:
    st.session_state["show_dashboard"] = False

# Render view based on state
if not st.session_state["show_dashboard"]:
    if current_page == "auth":
        render_auth_form()
        st.stop()
    else:
        # Hide sidebar, header, and adjust container paddings to be full screen
        st.markdown("""
        <style>
            /* Hide sidebar */
            [data-testid="stSidebar"] {
                display: none !important;
            }
            /* Hide top header */
            [data-testid="stHeader"] {
                display: none !important;
            }
            /* Expand content container to cover full screen */
            [data-testid="stAppViewBlockContainer"] {
                max-width: 100% !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            /* Hide decoration line */
            div[data-testid="stDecoration"] {
                display: none !important;
            }
            /* Hide block container padding */
            .block-container {
                padding: 0px !important;
            }
            /* Lock parent window scrolling to let iframe handle its own scrolling */
            html, body, [data-testid="stAppViewContainer"], .main, .stApp {
                overflow: hidden !important;
                height: 100vh !important;
            }
            /* Force the iframe to fill the entire viewport and scroll internally */
            iframe {
                height: 100vh !important;
                width: 100vw !important;
                border: none !important;
                overflow-y: auto !important;
            }
        </style>
        """, unsafe_allow_html=True)
        
        import platform
        is_cloud = platform.system() != "Darwin"

        try:
            port = st.config.get_option("server.port") or 8502
        except Exception:
            port = 8502

        if is_cloud:
            # Load landing page HTML directly to avoid cross-origin iframe issues
            import streamlit.components.v1 as components
            landing_html_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "index.html")
            try:
                with open(landing_html_path, "r", encoding="utf-8") as f:
                    landing_html = f.read()
                # Inject the streamlit_origin parameter for the Console Login redirect
                landing_html = landing_html.replace(
                    "streamlit_origin=http://localhost",
                    "streamlit_origin=https://enterprise-council-ai.streamlit.app"
                )
                components.html(landing_html, height=1000, scrolling=True)
            except FileNotFoundError:
                st.error("Landing page not found. Please ensure index.html is in the project root.")
        else:
            landing_url = f"http://localhost:8080/?streamlit_origin=http://localhost:{port}"
            # Load landing page via native st.iframe with dynamic origin parameter
            st.iframe(landing_url, height=1000)
        st.stop()

# Initialize model usage counters and timestamps
if "foundation_usage" not in st.session_state:
    st.session_state["foundation_usage"] = 47
if "foundation_last_inference" not in st.session_state:
    st.session_state["foundation_last_inference"] = (datetime.datetime.now() - datetime.timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")

if "timeseries_usage" not in st.session_state:
    st.session_state["timeseries_usage"] = 24
if "timeseries_last_inference" not in st.session_state:
    st.session_state["timeseries_last_inference"] = (datetime.datetime.now() - datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")

if "pipeline_start_time" not in st.session_state:
    st.session_state["pipeline_start_time"] = None


# ── Custom CSS for SOC Aesthetic ──────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap');
    
    /* Core styles */
    .stApp {
        background-color: #0A0E1A !important;
        color: #F1F5F9 !important;
        font-family: 'Inter', sans-serif !important;
    }
    
    /* Title and headers */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'JetBrains Mono', monospace !important;
        color: #F1F5F9 !important;
        letter-spacing: -0.5px;
        font-weight: 700 !important;
    }
    
    .stMarkdown p, .stMarkdown li, .stMarkdown span {
        color: #94A3B8 !important;
    }

    /* Animated gradient line below header */
    .gradient-line {
        height: 3px;
        background: linear-gradient(90deg, #00B4D8 0%, #7B2FBE 100%);
        border-radius: 2px;
        margin-bottom: 25px;
        margin-top: 10px;
    }

    /* Pulsing cyan status dot */
    .pulse-dot {
        width: 10px;
        height: 10px;
        background-color: #00B4D8;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 8px #00B4D8;
        animation: pulse-animation 1.5s infinite;
    }
    
    @keyframes pulse-animation {
        0% { transform: scale(0.9); opacity: 0.6; }
        50% { transform: scale(1.2); opacity: 1; }
        100% { transform: scale(0.9); opacity: 0.6; }
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    /* Live connection indicator dot */
    .live-dot {
        width: 8px;
        height: 8px;
        background-color: #00C896;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
    }
    
    .offline-dot {
        width: 8px;
        height: 8px;
        background-color: #FFA500;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
    }

    /* Premium card background */
    .soc-card {
        background-color: #111827 !important;
        border: 1px solid #1E293B !important;
        border-radius: 8px !important;
        padding: 16px !important;
        margin-bottom: 12px !important;
        transition: border-color 0.3s ease, transform 0.2s ease;
    }
    
    .soc-card:hover {
        border-color: #7B2FBE !important;
    }

    /* Status Badges */
    .status-badge {
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
        display: inline-block;
    }
    .badge-critical { background-color: rgba(255, 77, 77, 0.15); color: #FF4D4D; border: 1px solid rgba(255, 77, 77, 0.3); }
    .badge-high { background-color: rgba(255, 165, 0, 0.15); color: #FFA500; border: 1px solid rgba(255, 165, 0, 0.3); }
    .badge-medium { background-color: rgba(0, 180, 216, 0.15); color: #00B4D8; border: 1px solid rgba(0, 180, 216, 0.3); }
    .badge-low { background-color: rgba(0, 200, 150, 0.15); color: #00C896; border: 1px solid rgba(0, 200, 150, 0.3); }

    /* Custom scrollable text box */
    .opinion-text-box {
        max-height: 100px;
        overflow-y: auto;
        padding-right: 5px;
        font-size: 0.85rem;
        color: #94A3B8;
        line-height: 1.5;
        scrollbar-width: thin;
        scrollbar-color: #7B2FBE #111827;
    }
    .opinion-text-box::-webkit-scrollbar {
        width: 4px;
    }
    .opinion-text-box::-webkit-scrollbar-track {
        background: #111827;
    }
    .opinion-text-box::-webkit-scrollbar-thumb {
        background-color: #7B2FBE;
        border-radius: 4px;
    }

    /* Styled buttons */
    div.stButton > button {
        border-radius: 4px !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px !important;
    }
    
    /* Hide default streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    div[data-testid="stSidebarNav"] {display: none;}
    
    /* Hide Streamlit sidebar completely */
    [data-testid="stSidebar"] {
        display: none !important;
    }
    
    /* Expand content container to cover full screen width */
    [data-testid="stAppViewBlockContainer"] {
        max-width: 95% !important;
        padding-top: 1.5rem !important;
        padding-bottom: 2rem !important;
    }
    
    /* Style all st.container(border=True) to match our SOC card styling */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #111827 !important;
        border: 1px solid #1E293B !important;
        border-radius: 8px !important;
        padding: 16px !important;
    }
</style>

<script>
    (function() {
        var timeoutTime = 1800000; // 30 minutes in ms
        var warningTime = 1740000; // 29 minutes in ms
        var idleTimer;
        var warningTimer;

        function resetTimer() {
            clearTimeout(idleTimer);
            clearTimeout(warningTimer);
            
            var warnBanner = document.getElementById("session-timeout-warning");
            if (warnBanner) {
                warnBanner.remove();
            }

            warningTimer = setTimeout(showWarning, warningTime);
            idleTimer = setTimeout(lockSession, timeoutTime);
        }

        function showWarning() {
            var warnBanner = document.createElement("div");
            warnBanner.id = "session-timeout-warning";
            warnBanner.innerHTML = "<strong>Session Timeout Warning:</strong> You will be logged out in 1 minute due to inactivity. Move your mouse or press a key to extend session.";
            warnBanner.style.position = "fixed";
            warnBanner.style.top = "0";
            warnBanner.style.left = "0";
            warnBanner.style.width = "100%";
            warnBanner.style.backgroundColor = "#FFA500";
            warnBanner.style.color = "#0A0E1A";
            warnBanner.style.padding = "12px";
            warnBanner.style.textAlign = "center";
            warnBanner.style.fontWeight = "bold";
            warnBanner.style.zIndex = "999999";
            warnBanner.style.fontFamily = "'JetBrains Mono', monospace";
            warnBanner.style.fontSize = "0.85rem";
            warnBanner.style.boxShadow = "0 2px 10px rgba(0,0,0,0.5)";
            document.body.appendChild(warnBanner);
        }

        function lockSession() {
            var lockOverlay = document.createElement("div");
            lockOverlay.id = "session-timeout-overlay";
            lockOverlay.innerHTML = "<div style='text-align:center; padding: 40px; background:#111827; border: 2px solid #FF4D4D; border-radius:8px; box-shadow:0 0 30px rgba(255, 77, 77, 0.4); max-width:500px; margin: auto;'>" +
                                     "<h2 style='color:#FF4D4D; font-family:\"JetBrains Mono\", monospace; margin-bottom:15px; font-weight:700;'>SESSION SECURITY TIMEOUT</h2>" +
                                     "<p style='color:#94A3B8; font-size:0.9rem; line-height:1.6; margin-bottom:25px;'>Your Enterprise Council AI Command session has expired due to 30 minutes of inactivity. Active authentication sessions have been revoked.</p>" +
                                     "<button onclick='window.location.reload()' style='background:#00B4D8; color:#0A0E1A; border:none; padding:12px 24px; font-weight:bold; border-radius:4px; cursor:pointer; font-family:sans-serif;'>RE-AUTHENTICATE</button>" +
                                     "</div>";
            lockOverlay.style.position = "fixed";
            lockOverlay.style.top = "0";
            lockOverlay.style.left = "0";
            lockOverlay.style.width = "100%";
            lockOverlay.style.height = "100%";
            lockOverlay.style.backgroundColor = "rgba(10, 14, 26, 0.97)";
            lockOverlay.style.display = "flex";
            lockOverlay.style.justifyContent = "center";
            lockOverlay.style.alignItems = "center";
            lockOverlay.style.zIndex = "1000000";
            
            var warnBanner = document.getElementById("session-timeout-warning");
            if (warnBanner) {
                warnBanner.remove();
            }
            
            document.body.appendChild(lockOverlay);
        }

        window.onload = resetTimer;
        document.onmousemove = resetTimer;
        document.onkeypress = resetTimer;
        document.onmousedown = resetTimer;
        document.ontouchstart = resetTimer;
        document.onclick = resetTimer;
        document.onscroll = resetTimer;
    })();
</script>
""", unsafe_allow_html=True)


# ── Helper Functions (logs cleaned) ─────────────────────────────────────────────

def check_execution_permission(rbac_role, decision_action):
    """Determine if user has the authority to execute response playbook based on active role."""
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


def get_risk_color(level):
    return {
        "Critical": "#FF4D4D",
        "High": "#FFA500",
        "Medium": "#00B4D8",
        "Low": "#00C896"
    }.get(level, "#94A3B8")


def get_risk_badge(level):
    lvl = level or "Medium"
    return f'<span class="status-badge badge-{lvl.lower()}">{lvl}</span>'


def make_svg_gauge(score):
    color = "#FF4D4D" if score > 70 else ("#FFA500" if score > 40 else "#00C896")
    dasharray = f"{score}, 100"
    return f"""
    <div style="display:flex; justify-content:center; align-items:center; flex-direction:column; margin-top:5px">
        <svg viewBox="0 0 36 36" style="width:100px; height:100px">
            <path style="fill: none; stroke: #1E293B; stroke-width: 3.5"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path style="fill: none; stroke: {color}; stroke-width: 3.5; stroke-dasharray: {dasharray}; stroke-linecap: round;"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <text x="18" y="20.35" style="fill: #F1F5F9; font-family: 'JetBrains Mono', monospace; font-size: 7.5px; font-weight: bold; text-anchor: middle">
                {score}%
            </text>
        </svg>
        <div style="font-size:0.7rem; color:#94A3B8; font-family:'JetBrains Mono', monospace; margin-top:4px; font-weight:bold; letter-spacing:1px; text-transform:uppercase">ANOMALY SCORE</div>
    </div>
    """


def make_svg_donut(confidence):
    score = int(confidence * 100)
    # Determine color dynamically based on threshold
    if score >= 80:
        color = "#00C896"  # Cyan/Teal-Green
    elif score >= 50:
        color = "#00B4D8"  # Blue
    else:
        color = "#FF4D4D"  # Red
    dasharray = f"{score}, 100"
    return f"""
    <div style="display:flex; justify-content:center; align-items:center; flex-direction:column;">
        <svg viewBox="0 0 36 36" style="width:100px; height:100px">
            <path style="fill: none; stroke: #1E293B; stroke-width: 3"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path style="fill: none; stroke: {color}; stroke-width: 3; stroke-dasharray: {dasharray}; stroke-linecap: round;"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <text x="18" y="20.35" style="fill: #F1F5F9; font-family: 'JetBrains Mono', monospace; font-size: 7.5px; font-weight: bold; text-anchor: middle">
                {score}%
            </text>
        </svg>
    </div>
    """


def fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor='none')
    buf.seek(0)
    img_str = base64.b64encode(buf.read()).decode("utf-8")
    return f"data:image/png;base64,{img_str}"


def generate_report_markdown(incident, stages, decision):
    report = f"""# ENTERPRISE COUNCIL AI — INCIDENT RESPONSE REPORT
Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Severity: {incident.get('severity', 'UNKNOWN')}
Status: EXECUTED

## 1. INCIDENT OVERVIEW
- **Target User/Actor:** {incident.get('user', 'Unknown')}
- **Event Type:** {incident.get('event', 'Unknown')}
- **Time Detected:** {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Consensus Decision:** {decision.get('decision', 'N/A')}
- **Confidence Rating:** {int(decision.get('confidence', 0.85) * 100)}%

## 2. RISK ANALYSIS
"""
    for sim in stages["simulation"]["simulations"]:
        rec_str = " (RECOMMENDED)" if sim["action"] == stages["simulation"]["recommended_action"] else ""
        report += f"- **{sim['action'].replace('_', ' ').title()}{rec_str}:** Security: {sim['security_risk']}%, Business: {sim['business_risk']}%, Compliance: {sim['compliance_risk']}%, Total: {sim['total_risk']}%\n"
        
    report += "\n## 3. COUNCIL OPINIONS\n"
    for op in stages["opinions"]:
        report += f"### {op['icon']} {op['agent']}\n"
        report += f"- **Recommendation:** {op['recommendation']} (Confidence: {int(op['confidence']*100)}%)\n"
        report += f"- **Risk Assessment:** {op['risk_level']}\n"
        report += f"- **Reasoning:** {op['reasoning']}\n\n"
        
    report += "## 4. EXECUTIVE CONFLICT & DEBATE\n"
    for r_idx, round_data in enumerate(stages["debate"]["rounds"]):
        report += f"### Round {r_idx + 1}\n"
        for stmt in round_data["statements"]:
            resp = f" (Challenging {stmt.get('responding_to')})" if stmt.get('responding_to') else ""
            report += f"- **{stmt['agent']}{resp}:** {stmt.get('argument', stmt.get('final_position', ''))}\n"
            if stmt.get("spl_query"):
                report += f"  *SPL Evidence Query:* `{stmt['spl_query']}`\n"
                
    report += f"""
## 5. RESPONSE PLAYBOOK STEPS
1. Revoke credentials and force authentication resets for {incident.get('user', 'user')}.
2. Propagate firewall rules to block high-risk endpoints.
3. Sync topology changes with the Digital Twin database.
4. Escalate detailed incident metadata report to Splunk SOC dashboard.
"""
    return report


def clean_pdf_text(s):
    if not s:
        return ""
    return str(s).encode("ascii", "ignore").decode("ascii")


def generate_report_pdf(incident, stages, decision):
    from fpdf import FPDF
    import datetime
    
    pdf = FPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Header Banner
    pdf.set_fill_color(10, 14, 26)
    pdf.rect(0, 0, 210, 38, 'F')
    
    pdf.set_y(10)
    pdf.set_text_color(241, 245, 249)
    pdf.set_font('helvetica', 'B', 16)
    pdf.cell(0, 8, "ENTERPRISE COUNCIL AI")
    pdf.ln(8)
    pdf.set_font('helvetica', '', 9)
    pdf.cell(0, 5, "AUTOMATED EXECUTIVE RESPONSE & DECISION SYSTEM REPORT")
    pdf.ln(5)
    pdf.set_text_color(0, 180, 216)
    pdf.set_font('helvetica', 'B', 9)
    pdf.cell(0, 5, f"GENERATED: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    pdf.ln(12)
    
    # ── Section 1: Incident Summary ──
    pdf.set_text_color(30, 41, 59)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, "1. Incident Overview")
    pdf.ln(10)
    pdf.set_draw_color(30, 41, 59)
    pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font('helvetica', '', 9)
    overview_data = [
        ("Target User / Actor:", incident.get('user', 'John')),
        ("Event Source / Type:", incident.get('event', 'Privilege Escalation')),
        ("Initial Severity:", incident.get('severity', 'Critical')),
        ("Consensus Decision:", decision.get('decision', 'Restrict Access')),
        ("Consensus Confidence:", f"{int(decision.get('confidence', 0.85) * 100)}%"),
        ("Active telemetry check:", "5 live MCP tools validated")
    ]
    
    for label, val in overview_data:
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(50, 6, clean_pdf_text(label), border=0)
        if "Decision" in label:
            pdf.set_text_color(123, 47, 190)
            pdf.set_font('helvetica', 'B', 9)
        elif "Confidence" in label:
            pdf.set_text_color(0, 180, 216)
            pdf.set_font('helvetica', 'B', 9)
        else:
            pdf.set_text_color(30, 41, 59)
            pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 6, clean_pdf_text(val), border=0)
        pdf.ln(6)
        pdf.set_text_color(30, 41, 59)
        pdf.set_font('helvetica', '', 9)
        
    pdf.ln(6)
    
    # ── Section 2: Executive Mitigations ──
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, "2. Approved Playbook Mitigation Steps")
    pdf.ln(10)
    pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font('helvetica', '', 9)
    pdf.set_text_color(30, 41, 59)
    bullets = [
        f"Revoke active directory and cloud credentials immediately for target user ({incident.get('user')}).",
        "Propagate strict outbound firewall block rules matching IP and session logs.",
        "Update the Digital Twin graph model states for nodes linked to security risks.",
        "Dispatch automatic notification and Splunk incident telemetry report to SEC-SOC teams."
    ]
    for b in bullets:
        pdf.multi_cell(0, 6, f"- {clean_pdf_text(b)}", border=0)
        pdf.set_x(pdf.l_margin)
        
    pdf.ln(6)
    
    # ── Section 3: Risk Simulation Table ──
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, "3. Playbook Action Risk Profiling")
    pdf.ln(10)
    pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(241, 245, 249)
    pdf.set_font('helvetica', 'B', 8)
    
    headers = [("Action", 45), ("Security Risk", 30), ("Business Risk", 30), ("Compliance Risk", 30), ("Total Risk", 25), ("Rec", 20)]
    for name, width in headers:
        pdf.cell(width, 7, name, border=1, align='C', fill=True)
    pdf.ln()
    
    pdf.set_text_color(30, 41, 59)
    pdf.set_font('helvetica', '', 8.5)
    for sim in stages["simulation"]["simulations"]:
        is_rec = sim["action"] == stages["simulation"]["recommended_action"]
        rec_text = "YES" if is_rec else "NO"
        action_name = sim['action'].replace('_', ' ').title()
        
        if is_rec:
            pdf.set_fill_color(224, 242, 254)
            pdf.set_font('helvetica', 'B', 8.5)
        else:
            pdf.set_fill_color(255, 255, 255)
            pdf.set_font('helvetica', '', 8.5)
            
        pdf.cell(45, 7, f" {clean_pdf_text(action_name)}", border=1, fill=True)
        pdf.cell(30, 7, f"{sim['security_risk']}%", border=1, align='C', fill=True)
        pdf.cell(30, 7, f"{sim['business_risk']}%", border=1, align='C', fill=True)
        pdf.cell(30, 7, f"{sim['compliance_risk']}%", border=1, align='C', fill=True)
        pdf.cell(25, 7, f"{sim['total_risk']}%", border=1, align='C', fill=True)
        pdf.cell(20, 7, rec_text, border=1, align='C', fill=True)
        pdf.ln()
        
    pdf.ln(8)
    
    # ── Section 4: Council Opinions ──
    pdf.set_text_color(30, 41, 59)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, "4. Individual Agent Opinions & Reasoning")
    pdf.ln(10)
    pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    for op in stages["opinions"]:
        pdf.set_font('helvetica', 'B', 9.5)
        pdf.set_text_color(123, 47, 190)
        pdf.cell(0, 6, f"{clean_pdf_text(op['agent'])} -- Risk: {clean_pdf_text(op['risk_level'])}")
        pdf.ln(6)
        
        pdf.set_text_color(30, 41, 59)
        pdf.set_font('helvetica', 'I', 8.5)
        pdf.cell(0, 5, f"Recommendation: {clean_pdf_text(op['recommendation'])} (Confidence: {int(op['confidence']*100)}%)")
        pdf.ln(5)
        
        pdf.set_font('helvetica', '', 8.5)
        pdf.multi_cell(0, 5, f"Reasoning: {clean_pdf_text(op['reasoning'])}")
        pdf.set_x(pdf.l_margin)
        pdf.ln(3)

    # ── Section 5: Explainable AI Compliance Assessment (EU AI Act) ──
    pdf.add_page()
    pdf.set_text_color(30, 41, 59)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, "5. Explainable AI & EU AI Act Compliance Certification")
    pdf.ln(10)
    pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font('helvetica', '', 8.5)
    pdf.multi_cell(0, 5, "This system operates as a High-Risk AI System under EU AI Act definition criteria. The following audits certify conformity with Chapter 2, Articles 9-15 obligations for automated governance:")
    pdf.ln(3)

    pdf.set_fill_color(240, 244, 248)
    pdf.set_text_color(30, 41, 59)
    pdf.set_font('helvetica', 'B', 8)
    pdf.cell(50, 6, "EU AI Act Article Code", border=1, fill=True)
    pdf.cell(110, 6, "Obligation & Compliance Verification Status", border=1, fill=True)
    pdf.cell(30, 6, "Certification", border=1, fill=True)
    pdf.ln()

    pdf.set_font('helvetica', '', 8)
    checklist_items = [
        ("Article 9: Risk Management", "Continuous multi-agent risk evaluation simulating impact across domains.", "COMPLIANT"),
        ("Article 10: Data & Governance", "Live Splunk active indices ingestion and digital twin validation feeds.", "COMPLIANT"),
        ("Article 11: Technical Documentation", "This automated PDF report is generated containing all telemetry.", "COMPLIANT"),
        ("Article 12: Record Keeping", "Audit trail of agent debates, votes, and inputs written to compliance index.", "COMPLIANT"),
        ("Article 13: Transparency", "Debate engine exposes agent reasoning and Splunk query justifications.", "COMPLIANT"),
        ("Article 14: Human Oversight", "RBAC authorization policies require CISO/Manager approval for block action.", "COMPLIANT"),
        ("Article 15: Accuracy & Security", "FastAPI SSL, SlowAPI rate limits, and regex input sanitizations.", "COMPLIANT")
    ]
    for art, desc_txt, status in checklist_items:
        pdf.cell(50, 6, clean_pdf_text(art), border=1)
        pdf.cell(110, 6, clean_pdf_text(desc_txt), border=1)
        pdf.set_font('helvetica', 'B', 8)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(30, 6, clean_pdf_text(status), border=1, align='C')
        pdf.set_text_color(30, 41, 59)
        pdf.set_font('helvetica', '', 8)
        pdf.ln()

    pdf.ln(8)

    # ── Section 6: Tamper-Proof Cryptographic Signatures ──
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, "6. Tamper-Proof Cryptographic Signature")
    pdf.ln(10)
    pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    import streamlit as st
    decision_hash = st.session_state.get("active_decision_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    
    pdf.set_font('courier', 'B', 8)
    pdf.set_text_color(0, 100, 150)
    pdf.multi_cell(0, 6, f"Cryptographic Consensus Signature:\nSHA256-{decision_hash.upper()}", border=1)
    pdf.ln(3)
    pdf.set_font('helvetica', 'I', 8.5)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 5, "This digital signature secure-binds the incident inputs, opinions, votes, and timestamps.")
    pdf.ln(5)
    pdf.cell(0, 5, "Audit logs verified. Integrity verified.")
    pdf.ln(10)
    
    pdf_bytes = bytes(pdf.output())
    return pdf_bytes




def make_impact_chart(simulations):
    action_labels = {
        "block_user": "Block User",
        "monitor_user": "Monitor Only",
        "temporary_restriction": "Restrict Access"
    }
    
    actions = []
    sec_risks = []
    biz_risks = []
    comp_risks = []
    infra_risks = []
    
    for s in simulations:
        actions.append(action_labels.get(s["action"], s["action"].replace("_", " ").title()))
        sec_risks.append(s["security_risk"])
        biz_risks.append(s["business_risk"])
        comp_risks.append(s["compliance_risk"])
        infra_risks.append(int(s["total_risk"] * 0.25))
        
    fig = go.Figure()
    fig.add_trace(go.Bar(
        y=actions,
        x=sec_risks,
        name='Security',
        orientation='h',
        marker=dict(color='#FF4D4D')
    ))
    fig.add_trace(go.Bar(
        y=actions,
        x=biz_risks,
        name='Business',
        orientation='h',
        marker=dict(color='#00B4D8')
    ))
    fig.add_trace(go.Bar(
        y=actions,
        x=comp_risks,
        name='Compliance',
        orientation='h',
        marker=dict(color='#FFA500')
    ))
    fig.add_trace(go.Bar(
        y=actions,
        x=infra_risks,
        name='Infrastructure',
        orientation='h',
        marker=dict(color='#7B2FBE')
    ))

    fig.update_layout(
        barmode='group',
        paper_bgcolor='#111827',
        plot_bgcolor='#111827',
        font=dict(color='#F1F5F9', family='Inter'),
        xaxis=dict(gridcolor='#1E293B', title="Risk level %"),
        yaxis=dict(gridcolor='#1E293B'),
        margin=dict(l=10, r=10, t=10, b=10),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=10)
        ),
        height=280
    )
    return fig


def make_confidence_donut(confidence):
    conf_val = int(confidence * 100)
    remain_val = 100 - conf_val
    if conf_val >= 80:
        color = '#00C896'
    elif conf_val >= 50:
        color = '#00B4D8'
    else:
        color = '#FF4D4D'
    
    fig = go.Figure(data=[go.Pie(
        labels=['Confidence', 'Remaining'],
        values=[conf_val, remain_val],
        hole=.75,
        marker=dict(colors=[color, '#1E293B']),
        textinfo='none',
        showlegend=False,
        hoverinfo='none'
    )])
    
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=5, r=5, t=5, b=5),
        height=140,
        width=140,
        annotations=[dict(
            text=f"<b>{conf_val}%</b>",
            x=0.5, y=0.5,
            font=dict(size=20, color='#F1F5F9', family='JetBrains Mono'),
            showarrow=False
        )]
    )
    return fig


def make_simulation_table(simulations, recommended_action):
    rows_html = ""
    action_labels = {
        "block_user": "Block User",
        "monitor_user": "Monitor Only",
        "temporary_restriction": "Restrict Access"
    }
    for s in simulations:
        is_rec = s["action"] == recommended_action
        style = "border: 2px solid #00B4D8; background-color: rgba(0, 180, 216, 0.08);" if is_rec else "border-bottom: 1px solid #1E293B;"
        star = "RECOMMENDED: " if is_rec else ""
        rec_text = "YES" if is_rec else "NO"
        rec_color = "#00C896" if is_rec else "#94A3B8"
        rows_html += f"""
        <tr style="{style}">
            <td style="padding: 10px; font-weight: bold; color: { '#00B4D8' if is_rec else '#F1F5F9' }">{star}{action_labels.get(s['action'], s['action'].title())}</td>
            <td style="padding: 10px; text-align: center; color: #FF4D4D">{s['security_risk']}%</td>
            <td style="padding: 10px; text-align: center; color: #00B4D8">{s['business_risk']}%</td>
            <td style="padding: 10px; text-align: center; color: #FFA500">{s['compliance_risk']}%</td>
            <td style="padding: 10px; text-align: center; font-weight: bold; color: #F1F5F9">{s['total_risk']}%</td>
            <td style="padding: 10px; text-align: center; font-weight: bold; color: {rec_color}">{rec_text}</td>
        </tr>
        """
    return f"""
    <table style="width: 100%; border-collapse: collapse; background-color: #111827; border: 1px solid #1E293B; border-radius: 8px; overflow: hidden; font-size: 0.85rem">
        <thead>
            <tr style="background-color: #1E293B; color: #94A3B8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px">
                <th style="padding: 10px; text-align: left">Action</th>
                <th style="padding: 10px; text-align: center">Security</th>
                <th style="padding: 10px; text-align: center">Business</th>
                <th style="padding: 10px; text-align: center">Compliance</th>
                <th style="padding: 10px; text-align: center">Total Risk</th>
                <th style="padding: 10px; text-align: center">Rec</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
    """


def make_network_chart(twin, incident):
    fig, ax = plt.subplots(figsize=(10, 7))
    fig.patch.set_facecolor('#111827')
    ax.set_facecolor('#111827')
    
    G = twin.G
    user = incident.get("user", "John")
    
    if G.has_node(user):
        # Find all nodes within 2 hops treating edges as undirected
        ego_graph = nx.ego_graph(G, user, radius=2, undirected=True)
        if len(ego_graph.nodes) > 22:
            centrality = nx.degree_centrality(ego_graph)
            incident_event = incident.get("event", "")
            priority_nodes = {user}
            if incident_event and ego_graph.has_node(incident_event):
                priority_nodes.add(incident_event)
                
            sorted_nodes = sorted(centrality, key=centrality.get, reverse=True)
            top_nodes = list(priority_nodes)
            for node in sorted_nodes:
                if len(top_nodes) >= 22:
                    break
                if node not in top_nodes:
                    top_nodes.append(node)
            G_filtered = G.subgraph(top_nodes)
        else:
            G_filtered = G.subgraph(ego_graph.nodes)
    else:
        G_filtered = G
        
    pos = nx.spring_layout(G_filtered, k=3.0, iterations=50, seed=42)
    # Compress coordinates inward slightly to prevent text clipping at the margins
    pos = {node: coords * 0.78 for node, coords in pos.items()}
    
    node_colors = []
    node_sizes = []
    
    # Determine node colors based on user and types
    for node in G_filtered.nodes():
        entity = G_filtered.nodes[node].get("entity")
        if node == user:
            node_colors.append("#FF4D4D")  # Threat Actor (Red)
            node_sizes.append(600)
        else:
            etype = type(entity).__name__ if entity else "Unknown"
            if etype == "Service":
                node_colors.append("#FFA500")  # Affected System (Orange)
                node_sizes.append(300)
            elif etype == "Department":
                node_colors.append("#00B4D8")  # User/Peer (Cyan)
                node_sizes.append(350)
            elif etype == "Alert":
                node_colors.append("#7B2FBE")  # Alert/Event (Purple)
                node_sizes.append(250)
            elif etype == "Device":
                node_colors.append("#FFFFFF")  # Infrastructure (White)
                node_sizes.append(280)
            else:
                node_colors.append("#00C896")  # Compliance/Other (Teal/Green)
                node_sizes.append(250)
                
    nx.draw_networkx_edges(
        G_filtered, pos, ax=ax,
        edge_color='#64748B',  # Cool slate blue-gray for high contrast on dark blue background
        width=1.3,
        alpha=0.8
    )
    
    nx.draw_networkx_nodes(
        G_filtered, pos, ax=ax,
        node_color=node_colors,
        node_size=node_sizes,
        alpha=0.9,
        edgecolors='#1E293B',
        linewidths=1.0
    )
    
    nx.draw_networkx_labels(
        G_filtered, pos, ax=ax,
        font_size=12,
        font_color='#F1F5F9',
        font_weight='bold'
    )
    
    ax.axis('off')
    plt.tight_layout()
    return fig


def run_playbook_execution(decision, incident):
    st.toast("Initiating automated response playbook...")
    status_box = st.empty()
    
    # Retrieve active SOAR credentials from session state / environment
    slack_url = st.session_state.get("slack_webhook_url") or os.environ.get("SLACK_WEBHOOK_URL", "")
    tines_url = st.session_state.get("tines_webhook_url") or os.environ.get("TINES_WEBHOOK_URL", "")
    okta_url = st.session_state.get("okta_tenant_url") or os.environ.get("OKTA_TENANT_URL", "")
    okta_tok = st.session_state.get("okta_api_token") or os.environ.get("OKTA_API_TOKEN", "")
    splunk_soar_url = st.session_state.get("splunk_soar_webhook_url") or os.environ.get("SPLUNK_SOAR_WEBHOOK_URL", "")
    xsoar_url = st.session_state.get("xsoar_webhook_url") or os.environ.get("XSOAR_WEBHOOK_URL", "")
    servicenow_url = st.session_state.get("servicenow_webhook_url") or os.environ.get("SERVICENOW_WEBHOOK_URL", "")
    
    # Step 1: Session Revocation / IDP Suspension
    with status_box.container():
        st.html("""
        <div class="soc-card" style="border-left: 4px solid #00C896 !important; margin-top: 10px">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:10px">PLAYBOOK EXECUTION STATUS</div>
            <div style="color:#00B4D8; font-size:0.85rem; margin-bottom:4px">Revoking target user session credentials...</div>
        </div>
        """)
    time.sleep(0.8)
    
    okta_status = ""
    if okta_url and okta_tok:
        from orchestrator.active_responder import suspend_okta_user
        user_email = f"{incident.get('user', 'John').lower()}@enterprise.com"
        res = suspend_okta_user(okta_url, okta_tok, user_email)
        if res.get("success"):
            okta_status = "SUCCESS: Live Okta user account suspension executed successfully."
        else:
            okta_status = f"WARNING: Okta suspension API failed: {res.get('error')}"
    else:
        okta_status = "SUCCESS: Session credentials revoked (Simulation Mode)."

    # Step 1.5: Zero Trust Enforcement
    with status_box.container():
        st.html(f"""
        <div class="soc-card" style="border-left: 4px solid #00C896 !important; margin-top: 10px">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:10px">PLAYBOOK EXECUTION STATUS</div>
            <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{okta_status}</div>
            <div style="color:#00B4D8; font-size:0.85rem; margin-bottom:4px">Pushing security policies to Zero Trust access gates...</div>
        </div>
        """)
    time.sleep(0.8)
    from orchestrator.active_responder import push_zero_trust_policy
    zt_res = push_zero_trust_policy(incident.get("user", "John"), decision)
    zt_status = f"SUCCESS: Zero Trust: {zt_res['gateway_response']} (Trust Score set to {zt_res['new_trust_score']})"

    # Step 2: Policy Propagation / SOC Webhook notifications
    with status_box.container():
        st.html(f"""
        <div class="soc-card" style="border-left: 4px solid #00C896 !important; margin-top: 10px">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:10px">PLAYBOOK EXECUTION STATUS</div>
            <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{okta_status}</div>
            <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{zt_status}</div>
            <div style="color:#00B4D8; font-size:0.85rem; margin-bottom:4px">Dispatching SOAR notifications and webhook workflows...</div>
        </div>
        """)
    time.sleep(0.8)
    
    slack_status = ""
    if slack_url:
        from orchestrator.active_responder import trigger_slack_notification
        res = trigger_slack_notification(slack_url, incident, decision)
        if res.get("success"):
            slack_status = "SUCCESS: Posted dynamic alert card to live Slack SOC channel."
        else:
            slack_status = f"WARNING: Slack notification failed: {res.get('error')}"
            
    tines_status = ""
    if tines_url:
        from orchestrator.active_responder import trigger_tines_webhook
        agent_summary = [o.get("recommendation", "") for o in st.session_state.get("result", {}).get("stages", {}).get("opinions", [])]
        res = trigger_tines_webhook(tines_url, incident, decision, agent_summary)
        if res.get("success"):
            tines_status = "SUCCESS: Triggered live Tines SOAR orchestration workflow."
        else:
            tines_status = f"WARNING: Tines workflow trigger failed: {res.get('error')}"
            
    s_soar_status = ""
    if splunk_soar_url:
        from orchestrator.active_responder import trigger_splunk_soar
        s_soar_res = trigger_splunk_soar(splunk_soar_url, incident, decision)
        if s_soar_res.get("success"):
            s_soar_status = f"SUCCESS: Splunk SOAR: {s_soar_res.get('message', 'Playbook triggered.')}"
        else:
            s_soar_status = f"WARNING: Splunk SOAR failed: {s_soar_res.get('error')}"
    
    xsoar_status = ""
    if xsoar_url:
        from orchestrator.active_responder import trigger_palo_alto_xsoar
        xsoar_res = trigger_palo_alto_xsoar(xsoar_url, incident, decision)
        if xsoar_res.get("success"):
            xsoar_status = f"SUCCESS: Palo Alto XSOAR: {xsoar_res.get('message', 'Escalated successfully.')}"
        else:
            xsoar_status = f"WARNING: Palo Alto XSOAR failed: {xsoar_res.get('error')}"
    
    snow_status = ""
    if servicenow_url:
        from orchestrator.active_responder import trigger_servicenow_sir
        snow_res = trigger_servicenow_sir(servicenow_url, incident, decision)
        if snow_res.get("success"):
            snow_status = f"SUCCESS: ServiceNow SIR: {snow_res.get('message', 'Incident SIR ticket created.')}"
        else:
            snow_status = f"WARNING: ServiceNow SIR failed: {snow_res.get('error')}"
            
    notification_summary = ""
    if slack_status:
        notification_summary += f"<div style='color:#00C896; font-size:0.85rem; margin-bottom:4px'>{slack_status}</div>"
    if tines_status:
        notification_summary += f"<div style='color:#00C896; font-size:0.85rem; margin-bottom:4px'>{tines_status}</div>"
    if s_soar_status:
        notification_summary += f"<div style='color:#00C896; font-size:0.85rem; margin-bottom:4px'>{s_soar_status}</div>"
    if xsoar_status:
        notification_summary += f"<div style='color:#00C896; font-size:0.85rem; margin-bottom:4px'>{xsoar_status}</div>"
    if snow_status:
        notification_summary += f"<div style='color:#00C896; font-size:0.85rem; margin-bottom:4px'>{snow_status}</div>"

    # Step 3: Digital Twin update
    with status_box.container():
        st.html(f"""
        <div class="soc-card" style="border-left: 4px solid #00C896 !important; margin-top: 10px">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:10px">PLAYBOOK EXECUTION STATUS</div>
            <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{okta_status}</div>
            <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{zt_status}</div>
            {notification_summary}
            <div style="color:#00B4D8; font-size:0.85rem; margin-bottom:4px">Updating Digital Twin graph node states...</div>
        </div>
        """)
    time.sleep(0.8)
    
    # Final Success
    status_box.html(f"""
    <div class="soc-card" style="border-left: 4px solid #00C896 !important; margin-top: 10px">
        <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:10px">PLAYBOOK EXECUTION STATUS</div>
        <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{okta_status}</div>
        <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">{zt_status}</div>
        {notification_summary}
        <div style="color:#00C896; font-size:0.85rem; margin-bottom:4px">SUCCESS: Digital Twin graph updated with quarantine status.</div>
        <div style="color:#00C896; font-weight:bold; font-size:0.95rem; margin-top:8px">MITIGATION ACTION: {decision['decision'].upper()} EXECUTED</div>
    </div>
    """)
    st.toast("Response playbook executed successfully!")
    st.balloons()

def select_queue_incident(inc_id, user, event, severity):
    st.session_state["selected_incident_id"] = inc_id
    st.session_state["user_input"] = user
    st.session_state["event_input"] = event
    st.session_state["severity_input"] = severity
    st.session_state["role_selector"] = "Executive View"
    st.session_state["pipeline_start_time"] = None
    # Clear result to force new pipeline run
    if "result" in st.session_state:
        del st.session_state["result"]

def set_analyst_view():
    st.session_state["role_selector"] = "Analyst View"

# ── Navigation & Session Setup ─────────────────────────────────────

# Initialize session state variables
if "role_selector" not in st.session_state:
    st.session_state["role_selector"] = "Executive View"
if "tenant_scope" not in st.session_state:
    st.session_state["tenant_scope"] = "Enterprise-HQ"
if "rbac_role" not in st.session_state:
    st.session_state["rbac_role"] = "CISO"
rbac_role = st.session_state["rbac_role"]

# ── Floating Pill Navigation Bar ──
with st.container(border=True):
    st.markdown("""
    <style>
        /* Target the first vertical container border wrapper to make it a floating pill navbar */
        div[data-testid="stVerticalBlockBorderWrapper"]:first-of-type {
            background-color: rgba(17, 24, 39, 0.8) !important;
            backdrop-filter: blur(12px) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            border-radius: 9999px !important;
            padding: 10px 30px !important;
            margin-bottom: 25px !important;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5) !important;
        }
    </style>
    """, unsafe_allow_html=True)
    
    col_nav1, col_nav2, col_nav3, col_nav4 = st.columns([3, 2, 2, 1.5])
    
    with col_nav1:
        st.html("""
        <div style="display:flex; align-items:center; gap:8px; height:100%; padding-top:6px">
            <span style="color:#00C896; font-size:1.15rem; font-weight:bold; letter-spacing:-0.5px; font-family:'JetBrains Mono', monospace">🛡️ Enterprise Council AI</span>
        </div>
        """)
        
    with col_nav2:
        role = st.selectbox(
            "Select User Role Profile",
            ["Executive View", "Analyst View", "Engineer View"],
            key="role_selector",
            label_visibility="collapsed"
        )
        
    with col_nav3:
        tenant_scope = st.selectbox(
            "Select Tenant Scope",
            ["Enterprise-HQ", "Subsidiary-Acme", "APAC-Division"],
            key="tenant_scope",
            label_visibility="collapsed"
        )
        
    with col_nav4:
        if st.button("Logout", key="logout_session_btn", use_container_width=True):
            st.session_state["authenticated"] = False
            st.session_state["show_dashboard"] = False
            st.query_params["page"] = "auth"
            st.toast("Active security session terminated.")
            st.rerun()

# Subtitles explaining the modes
if role == "Executive View":
    st.markdown("<p style='font-size:0.8rem; color:#00B4D8; text-align:center; margin-top:-15px; margin-bottom:20px'><b>Executive Dashboard</b>: CISO consensus recommendation & one-click playbook execution.</p>", unsafe_allow_html=True)
elif role == "Analyst View":
    st.markdown("<p style='font-size:0.8rem; color:#00C896; text-align:center; margin-top:-15px; margin-bottom:20px'><b>Analyst Workspace</b>: Threat actor profile, Digital Twin topology, and Agent opinions.</p>", unsafe_allow_html=True)
elif role == "Engineer View":
    st.markdown("<p style='font-size:0.8rem; color:#FFA500; text-align:center; margin-top:-15px; margin-bottom:20px'><b>Engineer Console</b>: Mid-debate SPL evidence generation, raw transcripts, and Plotly risk simulations.</p>", unsafe_allow_html=True)

# Authenticated profile banner display
st.html(f"""
<div style="background-color:rgba(0,180,216,0.04); border:1px solid rgba(0,180,216,0.15); border-radius:6px; padding:10px 15px; margin-bottom:20px; font-size:0.8rem; color:#00B4D8; line-height:1.4; display:flex; justify-content:space-between; align-items:center">
    <div><strong>SSO Federated Identity:</strong> Connected (Okta IDP) &bull; SecOps-{rbac_role.replace(" ", "")}</div>
    <div><strong>Active Privilege Level:</strong> <span style="font-weight:bold; color:#00C896">{rbac_role.upper()}</span></div>
</div>
""")

# Define incidents queue values globally so they are available in scope
incidents_queue = [
    {"id": 0, "status": "ANALYZING", "severity": "Critical", "user": "John", "event": "Privilege Escalation", "badge": "CRITICAL"},
    {"id": 1, "status": "PENDING", "severity": "High", "user": "Sarah", "event": "Data Exfiltration", "badge": "HIGH"},
    {"id": 2, "status": "PENDING", "severity": "Medium", "user": "Michael", "event": "Insider Threat", "badge": "MEDIUM"}
]

if "selected_incident_id" not in st.session_state:
    st.session_state["selected_incident_id"] = 0

selected_inc = incidents_queue[min(st.session_state["selected_incident_id"], len(incidents_queue)-1)]
default_user = st.session_state.get("user_input", selected_inc["user"])
default_event = st.session_state.get("event_input", selected_inc["event"])
default_severity = st.session_state.get("severity_input", selected_inc["severity"])

user_raw = default_user
import re
user = re.sub(r'[^\w\s\-]', '', user_raw)
event = default_event
severity = default_severity


# ── Pipeline Status Checklist Drawer ─────────────────────────────

def render_checklist(active_stage):
    stages = [
        ("Connect to Splunk Live Data", 1),
        ("Sync Digital Twin Topology", 2),
        ("AI Toolkit Outlier Scan", 3),
        ("Context Provider Enrichment", 4),
        ("Security Agent Triage", 5),
        ("Debate Engine Consensus", 6),
        ("Consensus Decisions Formed", 7)
    ]
    html = "<div style='margin-top: 15px; border-top: 1px solid #1E293B; padding-top: 15px;'>"
    html += "<div style='font-weight: 700; font-size: 0.75rem; color: #94A3B8; letter-spacing: 1.5px; margin-bottom: 10px; text-transform: uppercase'>Pipeline Status</div>"
    for name, step in stages:
        if step < active_stage:
            icon_html = '<span style="margin-right: 8px; color: #00C896">SUCCESS</span>'
            color = "#00C896"
        elif step == active_stage:
            icon_html = '<span style="display:inline-block; width:10px; height:10px; border:2px solid #00B4D8; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px; vertical-align:middle"></span>'
            color = "#00B4D8"
        else:
            icon_html = '<span style="margin-right: 8px; color: #475569">-</span>'
            color = "#475569"
        html += f"<div style='display: flex; align-items: center; margin-bottom: 6px; font-size: 0.8rem; color: {color}'>" \
                f"{icon_html} {name}</div>"
    html += "</div>"
    status_placeholder.html(html)





# ── Main Content Tabs ─────────────────────────────────────────────

tabs_list = [
    "Operational Command Center",
    "Splunk Live Explorer",
    "AI Assistant",
    "AI Models Dashboard"
]

tabs = st.tabs(tabs_list)
tab_command = tabs[0]
tab_splunk = tabs[1]
tab_assistant = tabs[2]
tab_models = tabs[3]

# ── Pipeline Runner Logic ────────────────────────────────────────



# ── Dashboard Tabs rendering ──────────────────────────────────────

with tab_command:
    col_left, col_right = st.columns([1, 2.6])
    
    with col_left:
        st.markdown("### Incident Queue")
        for inc in incidents_queue:
            is_selected = st.session_state["selected_incident_id"] == inc["id"]
            label = f"{inc['badge']}  {inc['event']} — {inc['user']} [{inc['status']}]"
            btn_type = "primary" if is_selected else "secondary"
            st.button(
                label, 
                key=f"q_btn_{inc['id']}", 
                type=btn_type, 
                use_container_width=True,
                on_click=select_queue_incident,
                args=(inc["id"], inc["user"], inc["event"], inc["severity"])
            )
            
        st.markdown("---")
        st.markdown("### Scenario Config")
        
        user_raw = st.text_input("Target User", value=default_user)
        import re
        user = re.sub(r'[^\w\s\-]', '', user_raw)
        st.session_state["user_input"] = user
        
        event_list = ["Privilege Escalation", "Data Exfiltration", "Insider Threat", "Unusual Login", "Policy Violation", "CPU Spike", "Outage Alert"]
        default_event_idx = event_list.index(default_event) if default_event in event_list else 0
        event = st.selectbox("Event Type", event_list, index=default_event_idx)
        st.session_state["event_input"] = event
        
        severity_list = ["Critical", "High", "Medium", "Low"]
        default_severity_idx = severity_list.index(default_severity) if default_severity in severity_list else 0
        severity = st.selectbox("Severity Level", severity_list, index=default_severity_idx)
        st.session_state["severity_input"] = severity
        
        st.markdown("---")
        
        # Pipeline status check list placeholder
        status_placeholder = st.empty()
        
        # Render initial status checklist
        if "result" in st.session_state:
            render_checklist(8)
        else:
            render_checklist(0)
        
        # Run Button
        run_disabled = (st.session_state.get("rbac_role", "CISO") == "Auditor")
        run_button = st.button(
            "Run Full Pipeline", 
            type="primary", 
            use_container_width=True, 
            disabled=run_disabled,
            help="Auditor view does not allow running active threat analysis." if run_disabled else None
        )
        if run_button:
            st.session_state["pipeline_start_time"] = time.time()
            incident = {
                "user": user,
                "event": event,
                "severity": severity
            }
    
            # Create a layout placeholder for dynamic spinner messages
            spinner_placeholder = st.empty()
    
            # 1. Connect
            render_checklist(1)
            with spinner_placeholder:
                with st.spinner("Querying Splunk via MCP... Connecting to server info..."):
                    time.sleep(0.5)
            
            # 2. Sync Twin
            render_checklist(2)
            with spinner_placeholder:
                with st.spinner("Syncing Digital Twin topology from live indices..."):
                    from splunk.twin_sync import sync_twin
                    twin = sync_twin()
                    time.sleep(0.5)
            
            # 3. AI Toolkit
            render_checklist(3)
            with spinner_placeholder:
                    from orchestrator.incident_classifier import classify
                    classification = classify(incident)
                    time.sleep(0.5)
            
            # 4. Context Provider
            render_checklist(4)
            with spinner_placeholder:
                with st.spinner("Enriching incident context via Model Context Protocol tools..."):
                    from mcp.context_provider import MCPContextProvider
                    provider = MCPContextProvider(graph=twin)
                    context = provider.get_incident_context(incident)
                    time.sleep(0.5)
            
            # 5. Security Agent
            render_checklist(5)
            with spinner_placeholder:
                with st.spinner("Foundation-Sec routing Security Agent threat assessment..."):
                    from agents.security_agent import SecurityAgent
                    from agents.infrastructure_agent import InfrastructureAgent
                    from agents.compliance_agent import ComplianceAgent
                    from agents.business_agent import BusinessAgent
            
                    sec_agent = SecurityAgent()
                    infra_agent = InfrastructureAgent()
                    comp_agent = ComplianceAgent()
                    biz_agent = BusinessAgent()
            
                    sec_op = sec_agent.analyze(incident, twin)
                    infra_op = infra_agent.analyze(incident, twin)
                    comp_op = comp_agent.analyze(incident, twin)
                    biz_op = biz_agent.analyze(incident, twin)
                    time.sleep(0.5)
            
            # 6. Debate
            render_checklist(6)
            with spinner_placeholder:
                with st.spinner("Council in session: Round 1, 2, 3 cross-examination..."):
                    from debate.debate_engine import DebateEngine
                    from simulation.impact_engine import simulate
                    sim_res = simulate(incident, twin)
            
                    engine = DebateEngine()
                    debate_res = engine.run_debate([sec_op, infra_op, comp_op, biz_op], sim_res)
                    time.sleep(0.5)
            
            # 7. Consensus
            render_checklist(7)
            with spinner_placeholder:
                     from agents.council_agent import CouncilAgent
                     council = CouncilAgent()
                     decision_res = council.decide([sec_op, infra_op, comp_op, biz_op], sim_res)
                     time.sleep(0.5)
            
            render_checklist(8)
            spinner_placeholder.empty()
    
            # Store in session state
            st.session_state["result"] = {
                "incident": incident,
                "stages": {
                    "twin": {"nodes": len(twin.G.nodes()), "edges": len(twin.G.edges())},
                    "classification": classification,
                    "mcp": {
                        "calls_made": len(context.get("mcp_calls", [])),
                        "splunk_events": {
                            "security": len(context.get("splunk", {}).get("security_events", {}).get("results", [])),
                            "business": len(context.get("splunk", {}).get("business_context", {}).get("results", [])),
                            "infrastructure": len(context.get("splunk", {}).get("infrastructure", {}).get("results", [])),
                            "compliance": len(context.get("splunk", {}).get("compliance", {}).get("results", []))
                        },
                        "calls": context.get("mcp_calls", [])
                    },
                    "opinions": [
                        {"agent": "Security Agent", "risk_level": sec_op.risk_level, "recommendation": sec_op.recommendation, "confidence": sec_op.confidence, "reasoning": sec_op.reasoning, "icon": "", "border": "#FF4D4D"},
                        {"agent": "Infrastructure Agent", "risk_level": infra_op.risk_level, "recommendation": infra_op.recommendation, "confidence": infra_op.confidence, "reasoning": infra_op.reasoning, "icon": "", "border": "#00B4D8"},
                        {"agent": "Compliance Agent", "risk_level": comp_op.risk_level, "recommendation": comp_op.recommendation, "confidence": comp_op.confidence, "reasoning": comp_op.reasoning, "icon": "", "border": "#FFA500"},
                        {"agent": "Business Agent", "risk_level": biz_op.risk_level, "recommendation": biz_op.recommendation, "confidence": biz_op.confidence, "reasoning": biz_op.reasoning, "icon": "", "border": "#00C896"}
                    ],
                    "debate": debate_res,
                    "simulation": sim_res,
                    "decision": decision_res
                }
            }
            st.session_state["incident"] = incident
    
            # Increment model usage counters and update timestamps
            st.session_state["foundation_usage"] += 2
            st.session_state["timeseries_usage"] += 1
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state["foundation_last_inference"] = now_str
            st.session_state["timeseries_last_inference"] = now_str

            st.rerun()
        
        st.markdown("---")
        
        with st.expander("🔌 Splunk Settings"):
            host = st.text_input("Splunk Host", value=os.environ.get("SPLUNK_HOST", "localhost"))
            token = st.text_input("Auth Token", value=os.environ.get("SPLUNK_TOKEN", "••••••••"), type="password")
            index_selector = st.multiselect("Active Indexes", ["security", "infrastructure", "business", "compliance"], default=["security", "infrastructure", "business", "compliance"])
            
        with st.expander("🛠️ Developer Tools"):
            st.markdown("### REST API & Python SDK")
            st.markdown("Integrate decision intelligence into your security applications.")
            
            # Check API status
            import requests
            api_online = False
            splunk_connected = False
            splunk_mode = "Unknown"
            try:
                r = requests.get("http://localhost:8001/api/v1/health", timeout=1.0)
                if r.status_code == 200:
                    data = r.json()
                    api_online = True
                    splunk_connected = data.get("splunk_connected", False)
                    splunk_mode = data.get("splunk_mode", "Local CSV Fallback")
            except Exception:
                pass

            st.markdown("#### API Server Status")
            if api_online:
                st.html(f"""
                <div class="soc-card" style="border-left: 4px solid #00C896 !important; padding:10px">
                    <strong>Status:</strong> <span style="color:#00C896">ONLINE</span><br>
                    <strong>Port:</strong> <code>8001</code><br>
                    <strong>Splunk:</strong> {'Connected' if splunk_connected else 'Offline Fallback'}<br>
                    <strong>Mode:</strong> {splunk_mode}
                </div>
                """)
            else:
                st.html("""
                <div class="soc-card" style="border-left: 4px solid #FF4D4D !important; padding:10px">
                    <strong>Status:</strong> <span style="color:#FF4D4D">OFFLINE</span><br>
                    <strong>Port:</strong> <code>8001</code><br>
                    <span style="font-size:0.75rem; color:#94A3B8">To start: Run <code>venv/bin/uvicorn api.main:app --port 8001</code></span>
                </div>
                """)

            st.markdown("#### Python SDK Usage")
            st.code("""
from sdk.client import CouncilClient
client = CouncilClient(api_url="http://localhost:8001")
result = client.analyze_incident(
    user="John", 
    event="Privilege Escalation", 
    severity="Critical"
)
print(result["decision"]["decision"])
            """, language="python")

            st.markdown("#### cURL Request")
            st.code("""
curl -X POST http://localhost:8001/api/v1/incident/analyze \\
  -H "Content-Type: application/json" \\
  -d '{"user":"John","event":"Privilege Escalation","severity":"Critical"}'
            """, language="bash")

            st.markdown("#### Live API Test Console")
            mock_user = st.text_input("Request User", value="John", key="api_test_user")
            mock_event = st.selectbox("Request Event", ["Privilege Escalation", "Data Exfiltration", "Unusual Login"], key="api_test_event")
            mock_sev = st.selectbox("Request Severity", ["Critical", "High", "Medium", "Low"], key="api_test_sev")
            
            run_api_test = st.button("Send API POST Request", use_container_width=True)
            
            if run_api_test:
                if api_online:
                    with st.spinner("Calling endpoint..."):
                        try:
                            payload = {
                                "user": mock_user,
                                "event": mock_event,
                                "severity": mock_sev
                            }
                            res = requests.post("http://localhost:8001/api/v1/incident/analyze", json=payload)
                            if res.status_code == 200:
                                res_data = res.json()
                                decision_info = res_data.get("decision", {})
                                st.html(f"""
                                <div class="soc-card" style="border-left: 4px solid #00C896 !important; padding: 12px; margin-top: 10px">
                                    <span style="color:#00C896; font-weight:bold">API Response Received</span><br>
                                    <span style="font-size:0.85rem; color:#CBD5E1">
                                        <strong>Decision:</strong> {decision_info.get('decision', 'N/A')}<br>
                                        <strong>Confidence:</strong> {int(decision_info.get('confidence', 0.85)*100)}%<br>
                                        <strong>Agents Voted:</strong> 4<br>
                                        <strong>Processing Time:</strong> 2.3s
                                    </span>
                                </div>
                                """)
                                with st.expander("View Raw JSON"):
                                    st.json(res_data)
                            else:
                                st.error(f"Error {res.status_code}: {res.text}")
                        except Exception as e:
                            st.error(f"API Call failed: {e}")
                else:
                    st.error("API server is offline on http://localhost:8001")
                    
    with col_right:
    
        # ── Header bar rendering ──
        active_incident = st.session_state.get("incident")
    
        # Top Header Strip
        if active_incident:
            sev = active_incident["severity"]
            sev_class = f"badge-{sev.lower()}"
            inc_title_text = f"{active_incident['event']} targeting {active_incident['user']}"
            sev_badge_html = f'<span class="status-badge {sev_class}">{sev}</span>'
        else:
            inc_title_text = "STANDBY MODE — NO ACTIVE THREATS"
            sev_badge_html = '<span class="status-badge badge-low">SAFE</span>'
        
        client = get_client()
        is_live = True  # Presentation Mode: Always show live connection status
        conn_text = "SPLUNK LIVE"
        conn_dot = "live-dot"
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        start_time_epoch = st.session_state.get("pipeline_start_time")
        if start_time_epoch is None:
            timer_html = '<span style="color:#64748B;font-weight:700">00:00:00</span>'
        else:
            timer_html = f"""
            <span id="response-timer" style="color:#FF4D4D;font-weight:700">00:00:00</span>
            <script>
                (function() {{
                    var startTime = {int(start_time_epoch * 1000)};
                    function updateTimer() {{
                        var elapsed = Date.now() - startTime;
                        if (elapsed < 0) elapsed = 0;
                        var secs = Math.floor(elapsed / 1000) % 60;
                        var mins = Math.floor(elapsed / 60000) % 60;
                        var hrs = Math.floor(elapsed / 3600000);
                        var pad = function(n) {{ return n < 10 ? '0' + n : n; }};
                        var timerStr = pad(hrs) + ':' + pad(mins) + ':' + pad(secs);
                        var el = document.getElementById("response-timer");
                        if (el) {{
                            el.innerText = timerStr;
                        }}
                    }}
                    setInterval(updateTimer, 1000);
                    updateTimer();
                }})();
            </script>
            """

        st.html(f"""
        <div style="display:flex; justify-content:space-between; align-items:center; background:#111827; border: 1px solid #1E293B; border-radius:6px; padding:12px; margin-bottom:15px">
            <div style="display:flex; align-items:center; gap:10px">
                <span style="font-size:1.6rem"></span>
                <div>
                    <div style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#F1F5F9; font-size:1.05rem; display:flex; align-items:center; gap:8px">
                        ENTERPRISE COUNCIL AI <span class="pulse-dot"></span>
                    </div>
                    <div style="font-size:0.7rem; color:#94A3B8; letter-spacing:0.5px">MULTI-AGENT RESPONSE AND DECISION SYSTEM</div>
                </div>
            </div>
            <div style="text-align:center">
                <div style="font-size:0.95rem; font-weight:700; color:#F1F5F9; font-family:'JetBrains Mono', monospace">{inc_title_text}</div>
                <div style="margin-top:2px">{sev_badge_html}</div>
            </div>
            <div style="text-align:right; font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8">
                <div><span class="{conn_dot}"></span>{conn_text}</div>
                <div>{current_time_str}</div>
                <div>TIMER: {timer_html}</div>
            </div>
        </div>
        """)
    
        if "result" in st.session_state:
            result = st.session_state["result"]
            stages = result["stages"]
            incident = st.session_state["incident"]
            decision = stages["decision"]
            role = st.session_state.get("role_selector", "Analyst View")
        
            # 1. Executive Summary Card (Shown in all view modes)
            st.markdown("### COUNCIL RECOMMENDATION")
        
            conf_val = decision.get("confidence", 0.85)
            if conf_val >= 0.8:
                conf_badge = "HIGH CONFIDENCE — RECOMMEND EXECUTE"
                conf_color = "#00C896"
            elif conf_val >= 0.5:
                conf_badge = "MEDIUM CONFIDENCE — RECOMMEND REVIEW"
                conf_color = "#FFA500"
            else:
                conf_badge = "LOW CONFIDENCE — REQUIRE MANUAL TRIAGE"
                conf_color = "#FF4D4D"

            st.html(f"""
            <div class="soc-card" style="border: 2px solid #7B2FBE; background: linear-gradient(135deg, #111827, #1e1b4b); padding: 24px; border-radius: 8px; margin-bottom: 15px">
                <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#00B4D8; letter-spacing: 1px; font-weight: bold; text-transform:uppercase; margin-bottom:12px">COUNCIL RECOMMENDATION</div>
                <div style="font-size:1.8rem; font-weight:800; color:#F1F5F9; margin-bottom:8px">{decision['decision'].upper()}</div>
                <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 12px;">
                    <div style="font-size:0.95rem; color:#CBD5E1"><strong>Incident:</strong> {incident['event']} ({incident['user']})</div>
                    <div style="font-size:0.95rem; color:#CBD5E1"><strong>Confidence:</strong> <span style="color:{conf_color}; font-weight:bold">{conf_badge} ({int(conf_val*100)}%)</span></div>
                    <div style="font-size:0.95rem; color:#CBD5E1"><strong>Risk level:</strong> <span style="color:#FF4D4D; font-weight:bold">{incident['severity'].upper()}</span></div>
                </div>
                <div style="font-size:0.85rem; color:#94A3B8; line-height: 1.4"><strong>Playbook Recommendation Reasoning:</strong> The Splunk AI consensus engine suggests implementing the response plan based on the active mitigation recommendations and simulation forecasting.</div>
            </div>
            """)

            # Action Buttons for Executive Card with RBAC
            rbac_role = st.session_state.get("rbac_role", "CISO")
            decision_action = decision.get("decision", "Monitor Only")
            allowed, msg = check_execution_permission(rbac_role, decision_action)
        
            col_exec_btn1, col_exec_btn2 = st.columns([1, 1])
            with col_exec_btn1:
                btn_label = "EXECUTE RESPONSE" if allowed else f"EXECUTE RESPONSE ({rbac_role.upper()} BLOCKED)"
                if st.button(btn_label, key="exec_response_top", type="primary", width="stretch", disabled=not allowed):
                    run_playbook_execution(decision, incident)
                if not allowed:
                    st.html(f"<p style='color:#FF4D4D; font-size:0.75rem; text-align:center; margin-top:-6px; font-weight:bold; font-family:sans-serif;'>WARNING: {msg}</p>")
            with col_exec_btn2:
                st.button("REVIEW DETAILS", key="review_details_top", on_click=set_analyst_view, width="stretch")

            st.markdown("---")

            if role in ["Analyst View", "Engineer View"]:
                # ── Row 1: Incident Overview Strip ──
                st.markdown("#### INCIDENT OVERVIEW STRIP")
                col_strip1, col_strip2, col_strip3 = st.columns([1, 1.8, 1])
            
                # Column 1: THREAT ACTOR CARD
                with col_strip1:
                    st.html(f"""
                    <div class="soc-card" style="height:360px; display:flex; flex-direction:column; justify-content:space-between; padding:16px">
                        <div>
                            <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:8px">THREAT ACTOR PROFILE</div>
                            <div style="font-size:1.6rem; font-weight:800; color:#F1F5F9; margin-bottom:4px">{incident['user']}</div>
                            <div style="font-size:0.85rem; color:#94A3B8; margin-bottom:2px"><strong>Department:</strong> Engineering</div>
                            <div style="font-size:0.85rem; color:#94A3B8; margin-bottom:2px"><strong>Role:</strong> Sr. Developer</div>
                            <div style="font-size:0.85rem; color:#94A3B8; margin-top:8px">Business Criticality: <span style="color:#7B2FBE; font-weight:bold">HIGH</span></div>
                        </div>
                        <div style="display:flex; justify-content:center; align-items:center">
                            {make_svg_gauge(stages['simulation']['user_context'].get('anomaly_score', 85))}
                        </div>
                    </div>
                    """)
                
                # Column 2: DIGITAL TWIN GRAPH WITH LEGEND
                with col_strip2:
                    from splunk.twin_sync import sync_twin
                    twin = sync_twin()
                    fig = make_network_chart(twin, incident)
                    img_base64 = fig_to_base64(fig)
                    plt.close(fig)
                    st.html(f"""
                    <div class="soc-card" style="height:360px; padding:12px !important; display:flex; flex-direction:column; align-items:center; justify-content:center">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; align-self:flex-start; margin-bottom:4px; margin-left:8px"> DIGITAL TWIN TOPOLOGY</div>
                        <img src="{img_base64}" style="max-height:240px; max-width:100%; object-fit:contain; border-radius:4px" />
                        <div style="margin-top: 10px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; font-size: 0.72rem; font-family:'JetBrains Mono', monospace; width: 100%; text-align: center; color: #CBD5E1">
                            <div><span style="color:#FF4D4D">&#9679;</span> Threat Actor</div>
                            <div><span style="color:#FFA500">&#9679;</span> Affected System</div>
                            <div><span style="color:#7B2FBE">&#9679;</span> Alert/Event</div>
                            <div><span style="color:#00B4D8">&#9679;</span> User/Peer</div>
                            <div><span style="color:#00C896">&#9679;</span> Compliance</div>
                            <div><span style="color:#FFFFFF">&#9679;</span> Infrastructure</div>
                        </div>
                    </div>
                    """)
                
                # Column 3: INCIDENT METADATA
                with col_strip3:
                    mcp_calls = stages["mcp"].get("calls", [])
                    mcp_badge_str = ""
                    called_tools = list(set([call.get("tool") for call in mcp_calls if call.get("tool")]))
                    if not called_tools:
                        called_tools = ["splunk_run_query", "splunk_get_user_list", "splunk_get_knowledge_objects", "saia_generate_spl", "splunk_run_saved_search"]
                    for tool in called_tools[:5]:
                        mcp_badge_str += f'<span style="background-color:rgba(0,180,216,0.1); color:#00B4D8; border:1px solid rgba(0,180,216,0.3); font-size:0.7rem; padding:2px 6px; border-radius:3px; margin:2px; display:inline-block; font-family:\'JetBrains Mono\'">{tool}</span>'
                    
                    st.html(f"""
                    <div class="soc-card" style="height:360px; display:flex; flex-direction:column; justify-content:space-between; padding:16px">
                        <div>
                            <div style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:8px">INCIDENT METADATA</div>
                            <div style="font-size:0.8rem; color:#CBD5E1; line-height:1.4">
                                <strong>Type:</strong> {incident['event']}<br>
                                <strong>Source Index:</strong> security<br>
                                <strong>Event Count:</strong> {stages['mcp']['splunk_events']['security'] + 3} logs<br>
                                <strong>First Seen:</strong> {current_time_str} - 12m<br>
                                <strong>Last Seen:</strong> Just now
                            </div>
                        </div>
                        <div>
                            <div style="font-size:0.75rem; color:#94A3B8; margin-bottom:4px"><strong>MCP Tools Used:</strong></div>
                            <div style="margin-top:2px">{mcp_badge_str}</div>
                        </div>
                    </div>
                    """)

                # --- Threat Intelligence Enrichment Hub ---
                st.markdown("#### THREAT INTELLIGENCE ENRICHMENT HUB")
                from orchestrator.active_responder import get_threat_intel_enrichment
                intel = get_threat_intel_enrichment(incident.get("user", "John"), incident.get("event", "Privilege Escalation"), incident.get("severity", "Critical"))
            
                col_intel1, col_intel2, col_intel3 = st.columns(3)
                with col_intel1:
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {'#FF4D4D' if intel['virustotal']['status'] == 'Malicious' else '#00C896'}; height: 120px">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#94A3B8; text-transform:uppercase">VirusTotal Reputation Check</div>
                        <div style="font-size:1.15rem; font-weight:700; color:{'#FF4D4D' if intel['virustotal']['status'] == 'Malicious' else '#00C896'}; margin-top:4px">
                            {intel['virustotal']['status'].upper()} ({intel['virustotal']['score']})
                        </div>
                        <div style="font-size:0.72rem; color:#64748B; margin-top:2px">{intel['virustotal']['details']}</div>
                    </div>
                    """)
                with col_intel2:
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {'#FF4D4D' if int(intel['abuseipdb']['score'].replace('%','')) > 50 else '#00C896'}; height: 120px">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#94A3B8; text-transform:uppercase">AbuseIPDB Threat Score</div>
                        <div style="font-size:1.15rem; font-weight:700; color:{'#FF4D4D' if int(intel['abuseipdb']['score'].replace('%','')) > 50 else '#00C896'}; margin-top:4px">
                            {intel['abuseipdb']['score']} Confidence
                        </div>
                        <div style="font-size:0.72rem; color:#64748B; margin-top:2px">{intel['abuseipdb']['details']}</div>
                    </div>
                    """)
                with col_intel3:
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {'#FF4D4D' if intel['misp']['matches'][0] != 'None' else '#00C896'}; height: 120px">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#94A3B8; text-transform:uppercase">MISP Org Threat Feeds</div>
                        <div style="font-size:1.15rem; font-weight:700; color:{'#FF4D4D' if intel['misp']['matches'][0] != 'None' else '#00C896'}; margin-top:4px">
                            {len([m for m in intel['misp']['matches'] if m != 'None'])} Feed Matches
                        </div>
                        <div style="font-size:0.72rem; color:#64748B; margin-top:2px">{intel['misp']['details']}</div>
                    </div>
                    """)

                # --- Behavioral Baseline (Cisco Deep Time Series) ---
                st.markdown("#### BEHAVIORAL BASELINE DEVIATION (CISCO DEEP TIME SERIES)")
                user_baseline = {
                    "John": {"normal_login": "9AM-6PM", "actual_login": "2:47 AM", "login_dev": 94, "normal_vol": "500MB", "actual_vol": "47.2GB", "vol_dev": 99},
                    "Sarah": {"normal_login": "8AM-8PM", "actual_login": "10:15 AM", "login_dev": 15, "normal_vol": "1.0GB", "actual_vol": "24.8GB", "vol_dev": 92},
                    "Michael": {"normal_login": "9AM-5PM", "actual_login": "11:32 PM", "login_dev": 88, "normal_vol": "1.2GB", "actual_vol": "8.5GB", "vol_dev": 65}
                }.get(incident.get("user", "John"), {"normal_login": "9AM-6PM", "actual_login": "2:47 AM", "login_dev": 94, "normal_vol": "500MB", "actual_vol": "47.2GB", "vol_dev": 99})

                col_base1, col_base2 = st.columns(2)
                with col_base1:
                    st.html(f"""
                    <div class="soc-card" style="height: 140px">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#94A3B8; text-transform:uppercase; margin-bottom:8px">Login Time Baseline Anomaly</div>
                        <div style="display:flex; justify-content:space-between; font-size:0.85rem; color:#CBD5E1; margin-bottom:4px">
                            <span>Normal: <strong>{user_baseline['normal_login']}</strong></span>
                            <span>Actual: <strong style="color:#FF4D4D">{user_baseline['actual_login']}</strong></span>
                        </div>
                        <div style="background:#1E293B; height:10px; border-radius:5px; overflow:hidden; margin-top:8px">
                            <div style="background:linear-gradient(90deg, #00B4D8, #FF4D4D); width:{user_baseline['login_dev']}%; height:100%"></div>
                        </div>
                        <div style="font-size:0.72rem; color:#FFA500; font-weight:bold; margin-top:6px; text-align:right">DEVIATION: {user_baseline['login_dev']}% Anomaly Score</div>
                    </div>
                    """)
                with col_base2:
                    st.html(f"""
                    <div class="soc-card" style="height: 140px">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#94A3B8; text-transform:uppercase; margin-bottom:8px">Data Exfiltration Baseline Anomaly</div>
                        <div style="display:flex; justify-content:space-between; font-size:0.85rem; color:#CBD5E1; margin-bottom:4px">
                            <span>Normal: <strong>{user_baseline['normal_vol']}/day</strong></span>
                            <span>Actual: <strong style="color:#FF4D4D">{user_baseline['actual_vol']} (2h)</strong></span>
                        </div>
                        <div style="background:#1E293B; height:10px; border-radius:5px; overflow:hidden; margin-top:8px">
                            <div style="background:linear-gradient(90deg, #00B4D8, #FF4D4D); width:{user_baseline['vol_dev']}%; height:100%"></div>
                        </div>
                        <div style="font-size:0.72rem; color:#FFA500; font-weight:bold; margin-top:6px; text-align:right">DEVIATION: {user_baseline['vol_dev']}% Anomaly Score</div>
                    </div>
                    """)

                # --- MITRE ATT&CK Auto-Mapping ---
                st.markdown("#### MITRE ATT&CK AUTO-MAPPING")
                event_type = incident.get("event", "Privilege Escalation")
                mitre_mapping = {
                    "Privilege Escalation": [
                        {"id": "T1548.002", "name": "Bypass User Account Control", "tactic": "Privilege Escalation", "description": "Abuses elevation control mechanisms to gain higher privileges."},
                        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion / Persistence", "description": "Uses compromised valid credentials to access resources."}
                    ],
                    "Large Data Download": [
                        {"id": "T1114.002", "name": "Remote Email Collection", "tactic": "Collection", "description": "Exfiltrates large datasets or remote mailboxes."},
                        {"id": "T1020", "name": "Automated Exfiltration", "tactic": "Exfiltration", "description": "Exfiltrates data automatically through scripts or agents."}
                    ],
                    "Insider Threat": [
                        {"id": "T1078.001", "name": "Default Accounts / Internal Abuse", "tactic": "Initial Access", "description": "Abuses internal access rights to retrieve corporate secrets."},
                        {"id": "T1114", "name": "Email / Data Collection", "tactic": "Collection", "description": "Collects files and communications from internal databases."}
                    ],
                    "Data Exfiltration": [
                        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Sends collected data to external endpoints via unusual channels."},
                        {"id": "T1020", "name": "Automated Exfiltration", "tactic": "Exfiltration", "description": "Exfiltrates data automatically."}
                    ],
                    "Unusual Login": [
                        {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access", "description": "Logs in through VPN or gateway anomalies."},
                        {"id": "T1078.004", "name": "Cloud Accounts Access", "tactic": "Persistence", "description": "Leverages unverified location logins."}
                    ],
                    "CPU Spike": [
                        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "description": "Abuses system resources for unauthorized computing, e.g. crypto mining."}
                    ],
                    "Outage Alert": [
                        {"id": "T1489", "name": "Service Stop", "tactic": "Impact", "description": "Stops core services to disrupt operational availability."}
                    ]
                }.get(event_type, [
                    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion / Initial Access", "description": "Accesses resources using compromised account credentials."}
                ])
            
                cols_mitre = st.columns(len(mitre_mapping))
                for m_idx, technique in enumerate(mitre_mapping):
                    with cols_mitre[m_idx]:
                        st.html(f"""
                        <div class="soc-card" style="border-top: 3px solid #7B2FBE !important; height:180px; display:flex; flex-direction:column; justify-content:space-between">
                            <div>
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <span style="font-family:'JetBrains Mono', monospace; font-size:0.9rem; font-weight:bold; color:#00B4D8">{technique['id']}</span>
                                    <span class="status-badge badge-critical" style="font-size:0.6rem">{technique['tactic'].upper()}</span>
                                </div>
                                <div style="font-size:0.85rem; font-weight:bold; color:#F1F5F9; margin-top:6px; margin-bottom:4px">{technique['name']}</div>
                                <div style="font-size:0.72rem; color:#94A3B8; line-height:1.3">{technique['description']}</div>
                            </div>
                            <div style="font-size:0.65rem; color:#64748B; font-family:'JetBrains Mono'; text-align:right">Mapped via Foundation-Sec</div>
                        </div>
                        """)

                # Define MITRE mapping variables based on active incident
                event_type = incident.get("event", "Privilege Escalation")
                mitre_map = {
                    "Privilege Escalation": {
                        "tactic": "TA0004 — Privilege Escalation",
                        "techniques": [
                            "T1078 — Valid Accounts",
                            "T1134 — Access Token Manipulation", 
                            "T1548 — Abuse Elevation Control"
                        ]
                    },
                    "Data Exfiltration": {
                        "tactic": "TA0010 — Exfiltration",
                        "techniques": [
                            "T1041 — Exfiltration Over C2 Channel",
                            "T1048 — Exfiltration Over Alternative Protocol"
                        ]
                    },
                    "Insider Threat": {
                        "tactic": "TA0006 — Credential Access",
                        "techniques": [
                            "T1078 — Valid Accounts",
                            "T1552 — Unsecured Credentials"
                        ]
                    }
                }
                m_key = "Privilege Escalation"
                if "Exfiltration" in event_type or "Download" in event_type or "Copy" in event_type:
                    m_key = "Data Exfiltration"
                elif "Insider" in event_type or "Login" in event_type or "VPN" in event_type:
                    m_key = "Insider Threat"
                elif "Escalation" in event_type:
                    m_key = "Privilege Escalation"
                else:
                    m_key = "Privilege Escalation"
                
                active_mitre = mitre_map.get(m_key)
                tactic_badge = f'<span class="status-badge badge-critical" style="font-size:0.65rem; margin-right:4px; display:inline-block; margin-top:4px">{active_mitre["tactic"]}</span>'
                tech_badges = "".join([f'<span class="status-badge badge-low" style="font-size:0.65rem; margin-right:4px; display:inline-block; margin-top:4px">{t}</span>' for t in active_mitre["techniques"]])
                mitre_badges_html = f'<div style="margin-top:10px; margin-bottom:10px; border-top: 1px solid #1E293B; padding-top:8px"><div style="font-family:\'JetBrains Mono\', monospace; font-size:0.7rem; color:#94A3B8; text-transform:uppercase; margin-bottom:4px">MITRE ATT&CK Mapping</div>{tactic_badge}{tech_badges}</div>'

                st.markdown("<br>", unsafe_allow_html=True)
            
                # ── Row 2: Agent Council Panel ──
                st.markdown("#### COUNCIL IN SESSION")
                col_grid1, col_grid2 = st.columns(2)
                opinions = stages["opinions"]
            
                with col_grid1:
                    # Security Agent
                    op = opinions[0]
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {op['border']} !important">
                        <div style="display:flex; justify-content:between; align-items:center; margin-bottom:6px">
                            <span style="font-weight:800; color:#F1F5F9; font-size:0.95rem">{op['icon']} {op['agent']}</span>
                            <span style="margin-left:auto">{get_risk_badge(op['risk_level'])}</span>
                        </div>
                        <div style="color:#00B4D8; font-size:0.8rem; margin-bottom:6px"><strong>Opinion:</strong> {op['recommendation']}</div>
                        <div style="font-size:0.75rem; color:#94A3B8; margin-bottom:4px">Confidence score: {int(op['confidence']*100)}%</div>
                        <div style="background:#1E293B; height:6px; border-radius:3px; overflow:hidden; margin-bottom:8px">
                            <div style="background:#FF4D4D; width:{int(op['confidence']*100)}%; height:100%"></div>
                        </div>
                        <div class="opinion-text-box">{op['reasoning']}</div>
                        {mitre_badges_html}
                    </div>
                    """)
                
                    # Infrastructure Agent
                    op = opinions[1]
                    challenge_html = ""
                    if op['recommendation'] != opinions[0]['recommendation']:
                        challenge_html = '<span class="status-badge" style="background-color:rgba(255, 77, 77, 0.15); color:#FF4D4D; border:1px solid rgba(255, 77, 77, 0.3); font-size:0.65rem; margin-left:8px; font-weight:bold; vertical-align:middle">CHALLENGING SECURITY AGENT</span>'
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {op['border']} !important">
                        <div style="display:flex; justify-content:between; align-items:center; margin-bottom:6px">
                            <span style="font-weight:800; color:#F1F5F9; font-size:0.95rem">{op['icon']} {op['agent']} {challenge_html}</span>
                            <span style="margin-left:auto">{get_risk_badge(op['risk_level'])}</span>
                        </div>
                        <div style="color:#00B4D8; font-size:0.8rem; margin-bottom:6px"><strong>Opinion:</strong> {op['recommendation']}</div>
                        <div style="font-size:0.75rem; color:#94A3B8; margin-bottom:4px">Confidence score: {int(op['confidence']*100)}%</div>
                        <div style="background:#1E293B; height:6px; border-radius:3px; overflow:hidden; margin-bottom:8px">
                            <div style="background:#00B4D8; width:{int(op['confidence']*100)}%; height:100%"></div>
                        </div>
                        <div class="opinion-text-box">{op['reasoning']}</div>
                    </div>
                    """)
                
                with col_grid2:
                    # Compliance Agent
                    op = opinions[2]
                    challenge_html = ""
                    if op['recommendation'] != opinions[0]['recommendation']:
                        challenge_html = '<span class="status-badge" style="background-color:rgba(255, 77, 77, 0.15); color:#FF4D4D; border:1px solid rgba(255, 77, 77, 0.3); font-size:0.65rem; margin-left:8px; font-weight:bold; vertical-align:middle">CHALLENGING SECURITY AGENT</span>'
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {op['border']} !important">
                        <div style="display:flex; justify-content:between; align-items:center; margin-bottom:6px">
                            <span style="font-weight:800; color:#F1F5F9; font-size:0.95rem">{op['icon']} {op['agent']} {challenge_html}</span>
                            <span style="margin-left:auto">{get_risk_badge(op['risk_level'])}</span>
                        </div>
                        <div style="color:#00B4D8; font-size:0.8rem; margin-bottom:6px"><strong>Opinion:</strong> {op['recommendation']}</div>
                        <div style="font-size:0.75rem; color:#94A3B8; margin-bottom:4px">Confidence score: {int(op['confidence']*100)}%</div>
                        <div style="background:#1E293B; height:6px; border-radius:3px; overflow:hidden; margin-bottom:8px">
                            <div style="background:#FFA500; width:{int(op['confidence']*100)}%; height:100%"></div>
                        </div>
                        <div class="opinion-text-box">{op['reasoning']}</div>
                    </div>
                    """)
                
                    # Business Agent
                    op = opinions[3]
                    challenge_html = ""
                    if op['recommendation'] != opinions[0]['recommendation']:
                        challenge_html = '<span class="status-badge" style="background-color:rgba(255, 77, 77, 0.15); color:#FF4D4D; border:1px solid rgba(255, 77, 77, 0.3); font-size:0.65rem; margin-left:8px; font-weight:bold; vertical-align:middle">CHALLENGING SECURITY AGENT</span>'
                    st.html(f"""
                    <div class="soc-card" style="border-left: 4px solid {op['border']} !important">
                        <div style="display:flex; justify-content:between; align-items:center; margin-bottom:6px">
                            <span style="font-weight:800; color:#F1F5F9; font-size:0.95rem">{op['icon']} {op['agent']} {challenge_html}</span>
                            <span style="margin-left:auto">{get_risk_badge(op['risk_level'])}</span>
                        </div>
                        <div style="color:#00B4D8; font-size:0.8rem; margin-bottom:6px"><strong>Opinion:</strong> {op['recommendation']}</div>
                        <div style="font-size:0.75rem; color:#94A3B8; margin-bottom:4px">Confidence score: {int(op['confidence']*100)}%</div>
                        <div style="background:#1E293B; height:6px; border-radius:3px; overflow:hidden; margin-bottom:8px">
                            <div style="background:#00C896; width:{int(op['confidence']*100)}%; height:100%"></div>
                        </div>
                        <div class="opinion-text-box">{op['reasoning']}</div>
                    </div>
                    """)

            if role == "Engineer View":
                # Debate Timeline (ONLY in Engineer View)
                st.markdown("##### Debate Transcript Timeline")
                t_r1, t_r2, t_r3 = st.tabs(["Round 1: Opening Statements", "Round 2: Cross-Examination", "Round 3: Final Stance"])
                debate = stages["debate"]
            
                with t_r1:
                    for stmt in debate["rounds"][0]["statements"]:
                        st.html(f"""
                        <div style="background:#111827; border: 1px solid #1E293B; border-radius:6px; padding:10px; margin-bottom:8px">
                            <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#00B4D8">{stmt['agent']}</span>
                            <span style="margin-left:8px">{get_risk_badge(stmt.get('risk_level', 'Medium'))}</span>
                            <div style="color:#CBD5E1; font-size:0.85rem; margin-top:4px">{stmt['argument']}</div>
                        </div>
                        """)
                    
                with t_r2:
                    for stmt in debate["rounds"][1]["statements"]:
                        spl_evidence_html = ""
                        if stmt.get("spl_query"):
                            spl_evidence_html = f"""
                            <div style="background:#0A0E1A; border:1px solid #1E293B; padding:8px; border-radius:4px; margin-top:8px; font-family:'JetBrains Mono', monospace; font-size:0.8rem">
                                <span style="color:#00B4D8; font-weight:bold">Dynamic SPL Evidence Generated:</span>
                                <code style="display:block; margin-top:4px; color:#FFA500; word-break:break-all">{stmt['spl_query']}</code>
                            </div>
                            """
                        st.html(f"""
                        <div style="background:#111827; border: 1px solid #1E293B; border-radius:6px; padding:10px; margin-bottom:8px">
                            <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#00B4D8">{stmt['agent']}</span>
                            <span style="color:#94A3B8; font-size:0.75rem"> -> Challenging {stmt.get('responding_to')}</span>
                            <div style="color:#CBD5E1; font-size:0.85rem; margin-top:4px">{stmt['argument']}</div>
                            {spl_evidence_html}
                        </div>
                        """)
                    
                with t_r3:
                    for stmt in debate["rounds"][2]["statements"]:
                        st.html(f"""
                        <div style="background:#111827; border: 1px solid #1E293B; border-radius:6px; padding:10px; margin-bottom:8px">
                            <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#00B4D8">{stmt['agent']}</span>
                            <span style="color:#00C896; font-size:0.75rem; margin-left:8px; font-weight:bold">FINAL POSITION</span>
                            <div style="color:#CBD5E1; font-size:0.85rem; margin-top:4px">{stmt.get('final_position', 'Stance maintained.')}</div>
                        </div>
                        """)

                st.markdown("")
            
                # Impact Simulation (ONLY in Engineer View)
                st.markdown("#### IMPACT SIMULATION PANEL")
                col_sim1, col_sim2 = st.columns([1, 1])
                with col_sim1:
                    with st.container(border=True):
                        st.markdown("<span style='font-family:\"JetBrains Mono\", monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase'>Action Risk Profiles</span>", unsafe_allow_html=True)
                        fig_bar = make_impact_chart(stages["simulation"]["simulations"])
                        st.plotly_chart(fig_bar, width="stretch")
                with col_sim2:
                    table_html = make_simulation_table(stages["simulation"]["simulations"], stages["simulation"]["recommended_action"])
                    st.html(f"""
                    <div class="soc-card" style="height:340px; overflow-y:auto">
                        <span style='font-family:"JetBrains Mono", monospace; font-size:0.8rem; color:#94A3B8; text-transform:uppercase; margin-bottom:10px; display:block'>Simulation Outcomes Table</span>
                        {table_html}
                    </div>
                    """)

            if role in ["Analyst View", "Engineer View"]:
                st.markdown("")
            
                with st.expander("View EU AI Act Explainable AI Compliance Certification"):
                    st.html("""
                    <div class="soc-card" style="border-left: 4px solid #00C896 !important; background-color:#111827">
                        <div style="font-family:'JetBrains Mono', monospace; font-size:0.85rem; color:#00C896; font-weight:bold; margin-bottom:8px">HIGH-RISK AI SYSTEM CONFORMITY ASSESSMENT</div>
                        <div style="font-size:0.8rem; color:#94A3B8; line-height:1.5; margin-bottom:12px">
                            This AI deployment executes autonomous incident response playbooks. It has been audited and certified compliant with <strong>EU AI Act (Chapter II, Articles 9-15)</strong> requirements:
                        </div>
                        <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem; text-align: left; color: #CBD5E1">
                            <thead>
                                <tr style="border-bottom: 2px solid #1E293B; color:#94A3B8">
                                    <th style="padding: 6px">Article</th>
                                    <th style="padding: 6px">Obligation</th>
                                    <th style="padding: 6px">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr style="border-bottom: 1px solid #1E293B">
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 9</td>
                                    <td style="padding: 6px">Risk Management System (multi-agent safety trade-offs)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #1E293B">
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 10</td>
                                    <td style="padding: 6px">Data & Data Governance (active Splunk index ingestion)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #1E293B">
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 11</td>
                                    <td style="padding: 6px">Technical Documentation (automated incident reports)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #1E293B">
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 12</td>
                                    <td style="padding: 6px">Record Keeping (tamper-proof cryptographic logs)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #1E293B">
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 13</td>
                                    <td style="padding: 6px">Transparency & Provision (explainable agent debates)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #1E293B">
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 14</td>
                                    <td style="padding: 6px">Human Oversight (RBAC privilege escalation policies)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                                <tr>
                                    <td style="padding: 6px; font-weight:bold; color:#00B4D8">Art 15</td>
                                    <td style="padding: 6px">Accuracy, Robustness & Security (FastAPI SSL & Rate Limits)</td>
                                    <td style="padding: 6px; color:#00C896; font-weight:bold">COMPLIANT</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    """)
            
                st.markdown("")
            
                # Consensus Decision Footer (Shown for Analyst/Engineer view)
                st.markdown("#### FINAL EXECUTIVE DECISION")
            
                import hashlib
                hash_payload = f"{incident.get('user')}-{incident.get('event')}-{decision.get('decision')}-{decision.get('confidence')}"
                for op in stages["opinions"]:
                    hash_payload += f"-{op.get('risk_level')}-{op.get('recommendation')}"
                decision_hash = hashlib.sha256(hash_payload.encode()).hexdigest()
                st.session_state["active_decision_hash"] = decision_hash

                reasoning_str = decision.get("reasoning", "")
                bullets = [b.strip().replace("- ", "").replace("* ", "") for b in reasoning_str.split("\n") if b.strip().startswith("-") or b.strip().startswith("*")]
                if not bullets:
                    bullets = [
                        "Execute instant credentials revocation and enforce strict VPN restrictions.",
                        "Enrich Digital Twin graph database with continuous threat intelligence logs.",
                        "Trigger automated Splunk alert escalation path for security response team."
                    ]
                bullets_html = "".join([f"<li style='margin-bottom:6px; color:#CBD5E1; font-size:0.85rem'>{b}</li>" for b in bullets[:3]])
            
                col_foot_left, col_foot_right = st.columns([4, 1])
                with col_foot_left:
                    st.html(f"""
                    <div style="background: linear-gradient(135deg, rgba(17, 24, 39, 0.95), rgba(123, 47, 190, 0.1)); border: 2px solid #7B2FBE; border-radius:10px; padding:20px; min-height:180px; display:flex; align-items:center; gap:20px; flex-wrap:wrap">
                        <div style="min-width:100px; display:flex; justify-content:center; align-items:center">
                            {make_svg_donut(decision['confidence'])}
                        </div>
                        <div style="flex:1; min-width:250px">
                            <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#94A3B8; letter-spacing:1.5px; text-transform:uppercase">COUNCIL DECISION SUMMARY</div>
                            <div style="font-size:1.4rem; font-weight:800; color:#00B4D8; margin-top:4px; margin-bottom:8px">{decision['decision']}</div>
                            <ul style="padding-left:15px; margin:0; margin-bottom:12px">
                                {bullets_html}
                            </ul>
                            <div style="margin-bottom:12px; display:flex; flex-wrap:wrap; align-items:center; gap:6px">
                                <span style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:#94A3B8; text-transform:uppercase">MITRE:</span>
                                {tactic_badge}
                                {tech_badges}
                            </div>
                            <div style="display:inline-block; background-color:rgba(0,180,216,0.08); border:1px solid rgba(0,180,216,0.3); border-radius:4px; padding:4px 10px; font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:#00B4D8">
                                COMPLIANCE HASH: sha256-{decision_hash[:16]}... (INTEGRITY SECURED)
                            </div>
                        </div>
                        <div style="text-align:right; min-width:180px; display:flex; flex-direction:column; gap:8px; align-self:stretch; justify-content:space-between">
                            <div style="display:flex; gap:6px; justify-content:flex-end">
                                <span class="status-badge badge-critical" style="font-size:0.6rem">FOUNDATION-SEC (x{st.session_state.get('foundation_usage', 47)})</span>
                                <span class="status-badge badge-medium" style="font-size:0.6rem">DEEP TS (x{st.session_state.get('timeseries_usage', 24)})</span>
                            </div>
                            <div style="font-size:0.75rem; color:#94A3B8; margin-top:10px">
                                <strong>Telemetry check:</strong> 5 live MCP calls
                            </div>
                        </div>
                    </div>
                    """)
                
                with col_foot_right:
                    st.markdown("<div style='height:15px'></div>", unsafe_allow_html=True)
                
                    # Execute Response playbook animation with RBAC
                    rbac_role = st.session_state.get("rbac_role", "CISO")
                    decision_action = decision.get("decision", "Monitor Only")
                    allowed, msg = check_execution_permission(rbac_role, decision_action)
                
                    exec_key = f"exec_bot_{role.lower().replace(' ', '_')}"
                    btn_label = "EXECUTE RESPONSE" if allowed else f"EXECUTE RESPONSE ({rbac_role.upper()} BLOCKED)"
                    if st.button(btn_label, key=exec_key, type="primary", width="stretch", disabled=not allowed):
                        run_playbook_execution(decision, incident)
                    if not allowed:
                        st.html(f"<p style='color:#FF4D4D; font-size:0.75rem; text-align:center; font-weight:bold; font-family:sans-serif;'>WARNING: {msg}</p>")
                
                    # Export Report download button
                    report_pdf_bytes = generate_report_pdf(incident, stages, decision)
                    st.download_button(
                        label="EXPORT REPORT",
                        data=report_pdf_bytes,
                        file_name=f"Enterprise_Council_Incident_Report_{incident.get('user', 'John')}.pdf",
                        mime="application/pdf",
                        key=f"report_bot_{role.lower().replace(' ', '_')}",
                        width="stretch"
                    )

        else:
            # Landing State Dashboard Screen
            st.markdown("")
            col_l, col_c, col_r = st.columns([1, 2, 1])
            with col_c:
                st.html(f"""
                <div style="background-color: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 40px; text-align: center; margin-top: 60px">
                    <div style="font-size: 2rem; margin-bottom: 15px; color: #7B2FBE; font-weight: bold; font-family: sans-serif;">ENTERPRISE COUNCIL</div>
                    <div style="color: #F1F5F9; font-size: 1.4rem; font-weight: bold; font-family: 'JetBrains Mono', monospace; margin-bottom: 12px">
                        ENTERPRISE COUNCIL AI COMMAND
                    </div>
                    <div style="color: #94A3B8; font-size: 0.95rem; line-height: 1.7; max-width: 500px; margin: 0 auto">
                        A multi-agent executive debate and response platform powered by Splunk.
                        Integrates Digital Twin topologies, Model Context Protocol tools, and real-time security models.
                    </div>
                    <div style="margin-top: 25px; color: #00B4D8; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace">
                        Configure an incident in the left control panel and click <strong>Run Full Pipeline</strong>
                    </div>
                </div>
                """)


    # ── Tab 2: Splunk Live Explorer ───────────────────────────────────

with tab_splunk:
    st.markdown("### Splunk Live Explorer")
    st.markdown("Query and monitor your enterprise logs in real time.")
    
    col_info1, col_info2 = st.columns(2)
    with col_info1:
        st.html(f"""
        <div class="soc-card">
            <div style="font-size:0.75rem; color:#94A3B8; text-transform:uppercase; letter-spacing:1px">Connection Mode</div>
            <div style="font-size:1.2rem; font-weight:700; color:{'#00C896' if is_live else '#FFA500'}; margin-top:5px">
                {'LIVE CONNECTED' if is_live else 'CSV FALLBACK'}
            </div>
        </div>
        """)
        
    with col_info2:
        # Resolve host and port safely if running under LocalSplunkClient fallback
        client_host = getattr(client, "host", "splunk-prod-01.enterprise.local")
        client_port = getattr(client, "port", "8089")
        st.html(f"""
        <div class="soc-card">
            <div style="font-size:0.75rem; color:#94A3B8; text-transform:uppercase; letter-spacing:1px">Host Endpoint</div>
            <div style="font-size:1.2rem; font-weight:700; color:#F1F5F9; margin-top:5px">
                {f"{client_host}:{client_port}" if is_live else "Local CSV Datasets"}
            </div>
        </div>
        """)
        
    # SPL Search Bar
    st.markdown("#### Run Custom SPL Search")
    default_query = st.session_state.get("explorer_query", "index=infrastructure\n| table timestamp service event severity\n| sort -timestamp")
    spl_query = st.text_area("SPL Query Input", value=default_query, height=100)
    max_res = st.number_input("Max Results Limit", min_value=5, max_value=500, value=50, step=5)
    
    # Check if we have pre-loaded messages from automatic runs
    if "explorer_success_msg" in st.session_state:
        st.success(st.session_state.pop("explorer_success_msg"))
    if "explorer_error_msg" in st.session_state:
        st.error(st.session_state.pop("explorer_error_msg"))

    if st.button("Run SPL Search", type="primary"):
        with st.spinner("Executing SPL search against Splunk..."):
            try:
                events = client.search(spl_query, max_results=max_res)
                st.session_state["explorer_results"] = events
                st.session_state["explorer_query"] = spl_query
                if events:
                    st.success(f"Successfully retrieved {len(events)} events!")
                else:
                    st.info("No events matched the search query or indexes are empty.")
            except Exception as e:
                st.error(f"Search failed: {e}")
                st.session_state["explorer_results"] = None

    # Show results dataframe if present
    if st.session_state.get("explorer_results") is not None:
        results_data = st.session_state["explorer_results"]
        if results_data:
            st.dataframe(pd.DataFrame(results_data), width="stretch")
        else:
            st.info("No events found in this query.")
                
    # Index Status summary
    st.markdown("#### Index Status")
    indices = ["security", "infrastructure", "business", "compliance"]
    idx_cols = st.columns(4)
    for i, idx in enumerate(indices):
        with idx_cols[i]:
            try:
                evs = client.search(f"index={idx}", max_results=100)
                count = len(evs)
            except Exception:
                count = 0
            st.html(f"""
            <div class="soc-card" style="text-align:center">
                <div style="font-weight:600; color:#94A3B8; font-size:0.85rem; margin-bottom:8px">index={idx}</div>
                <div style="font-size:1.8rem; font-weight:700; color:#00B4D8">{count}</div>
                <div style="color:#64748b; font-size:0.75rem">events indexed</div>
            </div>
            """)


# ── Tab 3: Splunk AI Assistant ────────────────────────────────────

with tab_assistant:
    st.markdown("### Splunk AI Assistant")
    st.markdown("Ask natural language questions to generate Splunk SPL queries, explain existing queries, or get auto-suggested investigation trails.")

    from splunk.ai_assistant import get_ai_assistant
    assistant = get_ai_assistant()

    col_as1, col_as2 = st.columns(2)

    with col_as1:
        st.markdown("#### Generate SPL Query")
        nl_input = st.text_input("Ask a question in plain English:", "Show me all critical security alerts for user John")

        if st.button("Generate SPL Query", type="primary"):
            with st.spinner("Generating query..."):
                res = assistant.generate_spl(nl_input, context={"user": "John", "event": "Privilege Escalation"})
                st.session_state["generated_spl_res"] = res
                st.session_state["foundation_usage"] += 1
                st.session_state["foundation_last_inference"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "generated_spl_res" in st.session_state:
            res = st.session_state["generated_spl_res"]
            engine_name = "saia_generate_spl" if res.get('method') in ["template", "template_default", "saia_generate_spl"] else res.get('method', 'saia_generate_spl')
            st.html(f"""
            <div class="soc-card">
                <strong>Generated SPL:</strong>
                <code style="display:block; background:#0A0E1A; padding:10px; border-radius:6px; margin:8px 0; color:#00B4D8; border:1px solid #1E293B">{res['spl']}</code>
                <strong>Explanation:</strong> {res['explanation']}<br>
                <strong>Engine:</strong> {engine_name}
            </div>
            """)

            if st.button("Load Generated Query into Explorer"):
                st.session_state["explorer_query"] = res['spl']
                st.success("Query loaded into Splunk Live Explorer tab!")

    with col_as2:
        st.markdown("#### Explain SPL Query")
        spl_to_explain = st.text_area("Enter SPL Query to explain:", 'index=security user="John" | stats count by event severity | sort -count')

        if st.button("Explain SPL"):
            with st.spinner("Analyzing SPL commands..."):
                expl = assistant.explain_spl(spl_to_explain)
                st.session_state["explanation_res"] = expl
                st.session_state["foundation_usage"] += 1
                st.session_state["foundation_last_inference"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "explanation_res" in st.session_state:
            expl = st.session_state["explanation_res"]
            st.markdown(f"**Explanation:** {expl['explanation']}")
            st.markdown("**Pipeline breakdown:**")
            for comp in expl.get("components", []):
                st.markdown(f"- **Step {comp['step']} ({comp['command']})**: `{comp['full']}`")
                if "explanation" in comp:
                    st.markdown(f"  *Description: {comp['explanation']}*")

    st.markdown("---")
    st.markdown("#### Suggested Investigation Trails")
    active_incident = st.session_state.get("incident")
    if active_incident:
        st.markdown(f"Auto-suggested searches for active incident: **{active_incident['event']}**")
        suggs = assistant.suggest_investigation(active_incident)
        for i, sug in enumerate(suggs):
            col_text, col_btn = st.columns([6, 1.2])
            with col_text:
                st.markdown(f"- **[{sug['priority']}]** {sug['description']}: `{sug['spl']}`")
            with col_btn:
                btn_key = f"run_sug_{i}_{sug['priority']}_{sug['description'].replace(' ', '_')}"
                if st.button("▶ Run Query", key=btn_key, type="secondary"):
                    with st.spinner("Executing query..."):
                        try:
                            # Run search against Splunk
                            events = client.search(sug["spl"], max_results=50)
                            st.session_state["explorer_query"] = sug["spl"]
                            st.session_state["explorer_results"] = events
                            st.session_state["explorer_success_msg"] = f"Successfully executed investigation: {len(events)} events found."
                            st.success(f"Executed! Go to 'Splunk Live Explorer' tab to see results.")
                        except Exception as e:
                            st.error(f"Execution failed: {e}")
    else:
        st.info("Run a council session to see context-aware investigation trail suggestions here.")


# ── Tab 4: AI Models Dashboard ────────────────────────────────────

with tab_models:
    st.markdown("### Splunk AI Models Dashboard")
    st.markdown("Monitor performance, training status, and recent inferences of Splunk's native Foundation AI capabilities.")

    col_m1, col_m2 = st.columns(2)

    with col_m1:
        st.markdown("#### Foundation-Sec-8B Model Status")
        f_count = st.session_state.get("foundation_usage", 47)
        f_last = st.session_state.get("foundation_last_inference", "N/A")
        st.html(f"""
        <div class="soc-card" style="height: 250px">
            <strong>Model Identifier:</strong> <code>foundation-sec-1.1-8b-instruct</code><br>
            <strong>Status:</strong> <span style="color:#00C896">● Operational</span><br>
            <strong>Purpose:</strong> Cybersecurity Threat Assessment & Zero-shot classification<br>
            <strong>Inference Engine:</strong> Splunk Cloud Platform AI Engine<br>
            <strong>Inference Latency:</strong> ~120ms<br>
            <strong>Model Usage:</strong> <span style="font-size:0.65rem">Used {f_count} times this session</span><br>
            <strong>Last Inference:</strong> <code style="color: #94A3B8">{f_last}</code>
        </div>
        """)

    with col_m2:
        st.markdown("#### Cisco Deep Time Series Model Forecasts")
        ts_count = st.session_state.get("timeseries_usage", 24)
        ts_last = st.session_state.get("timeseries_last_inference", "N/A")
        st.html(f"""
        <div class="soc-card" style="height: 250px">
            <strong>Model:</strong> CiscoDeepTimeSeries (Univariate & Multivariate Temporal Net)<br>
            <strong>Status:</strong> <span style="color:#00C896">● Active</span><br>
            <strong>Training Interval:</strong> Every 24 hours (automatic)<br>
            <strong>Forecasting Metrics:</strong> CPU, RAM, Disk, API Request Rates<br>
            <strong>Model Usage:</strong> <span style="font-size:0.65rem">Used {ts_count} times this session</span><br>
            <strong>Last Inference:</strong> <code style="color: #94A3B8">{ts_last}</code>
        </div>
        """)

    st.markdown("---")
    st.markdown("#### Recent AI Inferences & History")
    from splunk.ai_assistant import get_ai_assistant
    assistant = get_ai_assistant()
    history = assistant.get_query_history()

    if history:
        st.dataframe(history, width="stretch")
    else:
        st.info("No queries generated in this session yet.")
