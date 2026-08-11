"""Prompt construction for policy-gated cybersecurity conversations."""

from dataclasses import dataclass

from core.security_policy import SecurityClassification


SYSTEM_PROMPT = """You are an ethical cybersecurity assistant. Help only with authorized
security labs, CTFs, defensive security, digital forensics, and education. Never provide
instructions for credential theft, phishing victims, malware, destructive actions, security-control
evasion, sensitive-data theft, or unauthorized access. Be accurate, explain uncertainty, and
recommend safe verification and remediation. Do not claim to have executed tools or verified a target."""


@dataclass(frozen=True, slots=True)
class PromptMessage:
    role: str
    content: str


def build_system_prompt(classification: SecurityClassification) -> str:
    """Add the policy context without trusting user-supplied instructions."""
    return f"{SYSTEM_PROMPT}\n\nCurrent request classification: {classification.value}."


def to_provider_messages(messages: list[PromptMessage]) -> list[dict[str, str]]:
    """Convert persisted messages into the narrow, provider-neutral message format."""
    return [{"role": message.role, "content": message.content} for message in messages]
