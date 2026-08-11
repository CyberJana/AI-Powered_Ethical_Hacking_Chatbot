"""Request classification and safety boundaries for security-assistance features."""

from dataclasses import dataclass
from enum import Enum
import re


class SecurityClassification(str, Enum):
    SAFE_EDUCATIONAL = "safe_educational"
    AUTHORIZED_LAB = "authorized_lab"
    DEFENSIVE = "defensive"
    FORENSICS = "forensics"
    HIGH_RISK = "high_risk"
    DISALLOWED = "disallowed"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    classification: SecurityClassification
    allowed: bool
    reason: str
    safe_alternative: str | None = None


class SecurityPolicy:
    """Classify requests before an AI provider or analysis module processes them."""

    _disallowed_patterns = (
        r"\b(?:steal|harvest|exfiltrate).{0,50}\b(?:credentials?|passwords?|tokens?|cookies?)\b",
        r"\b(?:phish|spearphish|credential[- ]?harvest)\b",
        r"\b(?:deploy|write|create).{0,40}\b(?:malware|ransomware|keylogger|backdoor)\b",
        r"\b(?:bypass|evade|disable).{0,50}\b(?:edr|antivirus|mfa|security control|logging)\b",
        r"\b(?:destroy|wipe|delete).{0,50}\b(?:data|database|backup|files)\b",
        r"\b(?:gain|get|obtain).{0,40}\b(?:unauthorized|illicit).{0,40}\baccess\b",
    )
    _high_risk_patterns = (
        r"\breverse shell\b",
        r"\bpersistence\b",
        r"\bexploit\b.{0,50}\b(?:production|real target|live target)\b",
        r"\bpassword cracking\b",
    )
    _forensics_patterns = (r"\bforensic", r"\bevidence\b", r"\bchain of custody\b", r"\b(?:disk|memory) image\b")
    _defensive_patterns = (
        r"\bmitigat",
        r"\bremediat",
        r"\bdetect",
        r"\bsecure coding\b",
        r"\blog analysis\b",
        r"\bincident response\b",
        r"\bharden",
    )
    _education_patterns = (
        r"\bwhat is\b",
        r"\bexplain\b",
        r"\blearn\b",
        r"\btutorial\b",
        r"\binterview question\b",
        r"\b(?:sql injection|xss|tcp/ip|osi model|cryptography)\b",
    )

    def classify(self, request: str, *, authorization_confirmed: bool = False) -> PolicyDecision:
        """Return a deterministic policy decision for non-empty user input."""
        normalized = request.strip().lower()
        if not normalized:
            return PolicyDecision(
                SecurityClassification.DISALLOWED,
                False,
                "A request is required before analysis can begin.",
            )

        if self._matches(normalized, self._disallowed_patterns):
            return PolicyDecision(
                SecurityClassification.DISALLOWED,
                False,
                "This assistant cannot help with credential theft, malware, destructive actions, "
                "security-control evasion, or unauthorized access.",
                "I can help you strengthen controls, analyze sanitized logs, or build an isolated lab exercise.",
            )

        if self._matches(normalized, self._high_risk_patterns):
            return PolicyDecision(
                SecurityClassification.HIGH_RISK,
                False,
                "This request requires controlled, authorized lab context and is not available here.",
                "I can explain detection and mitigation strategies or discuss the concept at a high level.",
            )

        if authorization_confirmed:
            return PolicyDecision(
                SecurityClassification.AUTHORIZED_LAB,
                True,
                "Authorized lab context was confirmed.",
            )
        if self._matches(normalized, self._forensics_patterns):
            return PolicyDecision(SecurityClassification.FORENSICS, True, "Forensics education is allowed.")
        if self._matches(normalized, self._defensive_patterns):
            return PolicyDecision(SecurityClassification.DEFENSIVE, True, "Defensive security guidance is allowed.")
        if self._matches(normalized, self._education_patterns):
            return PolicyDecision(
                SecurityClassification.SAFE_EDUCATIONAL,
                True,
                "Educational cybersecurity guidance is allowed.",
            )
        return PolicyDecision(
            SecurityClassification.SAFE_EDUCATIONAL,
            True,
            "General cybersecurity education is allowed.",
        )

    @staticmethod
    def _matches(text: str, patterns: tuple[str, ...]) -> bool:
        return any(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL) for pattern in patterns)
