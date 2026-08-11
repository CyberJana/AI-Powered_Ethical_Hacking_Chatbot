"""Phase-one Streamlit security operations dashboard."""

import streamlit as st

from core.config import get_settings
from database.database import SessionLocal, initialize_database
from database.repositories import DashboardRepository
from ui.chat import render_chat
from ui.code_analysis import render_code_analysis
from ui.ethical_hacking import render_ethical_hacking
from ui.lab import render_lab
from ui.vulnerability import render_vulnerability


def render_application() -> None:
    """Render the application shell and currently available modules."""
    settings = get_settings()
    initialize_database()
    st.set_page_config(page_title=settings.app_name, page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        .stApp { background: #09111f; color: #e6edf3; }
        [data-testid="stMetric"] {
            background: #101b2d; border: 1px solid #1f3a5f; border-radius: 10px; padding: 16px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.header("Navigation")
    page = st.sidebar.radio(
        "Module",
        ("Dashboard", "AI Chat", "Ethical Hacking", "Authorized Lab", "Vulnerability Analyzer", "Code Analyzer"),
    )
    st.sidebar.caption(f"Environment: {settings.environment}")
    if page == "AI Chat":
        render_chat()
        return
    if page == "Ethical Hacking":
        render_ethical_hacking()
        return
    if page == "Authorized Lab":
        render_lab()
        return
    if page == "Vulnerability Analyzer":
        render_vulnerability()
        return
    if page == "Code Analyzer":
        render_code_analysis()
        return
    if page != "Dashboard":
        st.title(page)
        st.info("This module is planned for a subsequent phase.")
        return

    st.title("AI-Powered Ethical Hacking Chatbot")
    st.caption("Authorized security labs, defensive analysis, and cybersecurity education.")

    with SessionLocal() as session:
        stats = DashboardRepository().get_statistics(session)

    cards = st.columns(5)
    cards[0].metric("Conversations", stats.total_conversations)
    cards[1].metric("Investigations", stats.investigations)
    cards[2].metric("Findings", stats.findings)
    cards[3].metric("High Severity", stats.high_severity_findings)
    cards[4].metric("Reports", stats.reports_generated)

    st.subheader("Phase 5 workspace")
    st.info(
        "The policy-gated AI chat, learning content, lab interpreter, vulnerability analysis, and code review are ready. "
        "Log analysis, forensics, RAG, and reporting modules will be introduced in subsequent phases."
    )
