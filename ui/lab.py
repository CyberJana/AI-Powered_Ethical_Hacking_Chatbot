"""Authorized-lab results interpretation UI."""

import streamlit as st

from modules.lab_assistant import AuthorizedLabAssistant


def render_lab() -> None:
    """Collect explicit authorization and locally interpret pasted output."""
    st.header("Authorized Lab Assistant")
    st.caption("Paste results you already collected. This page does not run tools or contact targets.")
    with st.form("lab-analysis"):
        lab_name = st.text_input("Lab name", max_chars=120)
        target_type = st.selectbox("Target type", ("CTF host", "Training web application", "Sandbox service", "Other lab"))
        target = st.text_input("Target IP or domain", max_chars=253)
        objective = st.text_input("Lab objective", max_chars=300)
        authorization = st.checkbox("I confirm I am authorized to assess this lab target.")
        results = st.text_area("Paste collected results", max_chars=20_000, height=240)
        submitted = st.form_submit_button("Interpret results")

    if submitted:
        if not all((lab_name.strip(), target.strip(), objective.strip(), results.strip())):
            st.error("Lab name, target, objective, and collected results are required.")
            return
        analysis = AuthorizedLabAssistant().interpret(
            lab_name=lab_name,
            target_type=target_type,
            target=target,
            objective=objective,
            results=results,
            authorization_confirmed=authorization,
        )
        if not analysis.allowed:
            st.warning(analysis.summary)
            return
        st.success(analysis.summary)
        for finding in analysis.findings:
            with st.expander(f"{finding.severity.upper()}: {finding.title}"):
                st.write(f"**Evidence:** {finding.evidence}")
                st.write(f"**Recommended next step:** {finding.recommendation}")
