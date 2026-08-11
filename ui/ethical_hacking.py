"""Learning-module presentation."""

import streamlit as st

from modules.ethical_hacking import get_topic, list_topics


def render_ethical_hacking() -> None:
    """Render one structured learning topic at a time."""
    st.header("Ethical Hacking Learning")
    topics = list_topics()
    selected_slug = st.selectbox("Topic", [topic.slug for topic in topics], format_func=lambda slug: get_topic(slug).title)
    topic = get_topic(selected_slug)
    st.caption(topic.category)
    st.subheader("Definition")
    st.write(topic.definition)
    st.subheader("Objective")
    st.write(topic.objective)
    st.subheader("Theory")
    st.write(topic.theory)
    st.subheader("Authorized lab example")
    st.info(topic.authorized_lab_example)
    first, second = st.columns(2)
    with first:
        st.subheader("Detection")
        st.write(topic.detection_methodology)
    with second:
        st.subheader("Mitigation")
        st.write(topic.mitigation)
    st.subheader("Interview questions")
    for question in topic.interview_questions:
        st.write(f"- {question}")
    st.subheader("Practice questions")
    for question in topic.practice_questions:
        st.write(f"- {question}")
