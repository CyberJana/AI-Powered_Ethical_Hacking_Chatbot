import pytest

from core.security_policy import SecurityClassification
from modules.ethical_hacking import get_topic, list_topics
from modules.lab_assistant import AuthorizedLabAssistant


def test_learning_topics_include_structured_content() -> None:
    topic = get_topic("web-security")

    assert len(list_topics()) >= 6
    assert topic.authorized_lab_example
    assert topic.mitigation
    assert topic.practice_questions


def test_missing_topic_raises_clear_error() -> None:
    with pytest.raises(LookupError):
        get_topic("missing-topic")


def test_lab_results_require_authorization() -> None:
    analysis = AuthorizedLabAssistant().interpret(
        lab_name="Demo",
        target_type="CTF host",
        target="10.0.0.5",
        objective="Review service exposure",
        results="80/tcp open http",
        authorization_confirmed=False,
    )

    assert analysis.allowed is False
    assert analysis.classification == SecurityClassification.HIGH_RISK


def test_authorized_lab_interprets_supplied_results_without_actions() -> None:
    analysis = AuthorizedLabAssistant().interpret(
        lab_name="Demo",
        target_type="CTF host",
        target="10.0.0.5",
        objective="Review service exposure",
        results="80/tcp open http\nServer: demo\nContent-Type: text/html",
        authorization_confirmed=True,
    )

    assert analysis.allowed is True
    assert len(analysis.findings) == 2
    assert "No network actions" in analysis.summary
