import pytest

from modules.code_analyzer import CodeAnalyzer


def test_code_analyzer_finds_injection_and_hard_coded_secret() -> None:
    findings = CodeAnalyzer().analyze(
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\npassword = "not-a-secret"',
        file_name="example.py",
    )

    assert [finding.finding_id for finding in findings] == ["CODE-001", "CODE-005"]
    assert findings[0].line_number == 1
    assert findings[0].file == "example.py"


def test_code_analyzer_finds_unsafe_deserialization() -> None:
    findings = CodeAnalyzer().analyze("value = pickle.loads(payload)")

    assert findings[0].finding_id == "CODE-004"
    assert findings[0].severity == "high"


def test_code_analyzer_requires_source() -> None:
    with pytest.raises(ValueError):
        CodeAnalyzer().analyze("   ")
