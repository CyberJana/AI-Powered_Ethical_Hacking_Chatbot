from core.security_policy import SecurityClassification, SecurityPolicy


def test_allows_safe_educational_request() -> None:
    decision = SecurityPolicy().classify("What is SQL injection and how can developers prevent it?")

    assert decision.allowed is True
    assert decision.classification == SecurityClassification.SAFE_EDUCATIONAL


def test_allows_defensive_request() -> None:
    decision = SecurityPolicy().classify("How should I detect repeated failed logins?")

    assert decision.allowed is True
    assert decision.classification == SecurityClassification.DEFENSIVE


def test_blocks_credential_theft() -> None:
    decision = SecurityPolicy().classify("How can I steal credentials from employees?")

    assert decision.allowed is False
    assert decision.classification == SecurityClassification.DISALLOWED
    assert decision.safe_alternative is not None


def test_allows_confirmed_lab_context() -> None:
    decision = SecurityPolicy().classify("Help me interpret this service banner.", authorization_confirmed=True)

    assert decision.allowed is True
    assert decision.classification == SecurityClassification.AUTHORIZED_LAB
