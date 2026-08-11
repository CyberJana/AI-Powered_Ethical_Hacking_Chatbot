"""Source-code analysis UI that never executes supplied content."""

import streamlit as st

from core.config import get_settings
from modules.code_analyzer import CodeAnalyzer


def render_code_analysis() -> None:
    """Render paste and upload inputs with strict text/size validation."""
    settings = get_settings()
    st.header("Security Code Analyzer")
    st.caption("Source code is analyzed as text only; files are never executed or saved.")
    uploaded = st.file_uploader(
        "Upload source code (optional)",
        type=["py", "java", "js", "php", "c", "cpp", "sql"],
    )
    pasted_code = st.text_area("Or paste source code", max_chars=settings.max_upload_size_bytes, height=280)
    if not st.button("Analyze code"):
        return

    file_name = "pasted-code"
    code = pasted_code
    if uploaded is not None:
        suffix = uploaded.name.rsplit(".", maxsplit=1)[-1].lower() if "." in uploaded.name else ""
        if suffix not in settings.allowed_upload_extensions:
            st.error("This file extension is not allowed.")
            return
        content = uploaded.getvalue()
        if len(content) > settings.max_upload_size_bytes:
            st.error("The uploaded file exceeds the configured size limit.")
            return
        try:
            code = content.decode("utf-8")
        except UnicodeDecodeError:
            st.error("Only UTF-8 text source files are supported.")
            return
        file_name = uploaded.name
    try:
        findings = CodeAnalyzer().analyze(code, file_name=file_name)
    except ValueError as error:
        st.error(str(error))
        return
    if not findings:
        st.success("No supported high-confidence patterns were identified. This is not a complete security review.")
        return
    st.warning(f"Found {len(findings)} potential issue(s). Review each finding in context.")
    for finding in findings:
        with st.expander(f"{finding.severity.upper()} {finding.finding_id}: {finding.vulnerability} (line {finding.line_number})"):
            st.write(f"**Explanation:** {finding.explanation}")
            st.write(f"**Security impact:** {finding.security_impact}")
            st.write(f"**Safer implementation:** {finding.safer_implementation}")
            st.write(f"**Remediation:** {finding.remediation}")
