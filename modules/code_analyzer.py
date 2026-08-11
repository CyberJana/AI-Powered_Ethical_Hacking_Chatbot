"""Non-executing, pattern-based source-code security review."""

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class CodeFinding:
    finding_id: str
    file: str
    line_number: int
    vulnerability: str
    severity: str
    explanation: str
    security_impact: str
    safer_implementation: str
    remediation: str


@dataclass(frozen=True, slots=True)
class _Rule:
    finding_id: str
    pattern: re.Pattern[str]
    vulnerability: str
    severity: str
    explanation: str
    impact: str
    safer_implementation: str
    remediation: str


class CodeAnalyzer:
    """Detect clear common weaknesses in supplied text without interpreting it."""

    _rules = (
        _Rule(
            "CODE-001",
            re.compile(r"\b(?:execute|query)\s*\(\s*(?:f[\"']|[\"'].*(?:\+|%))", re.IGNORECASE),
            "Potential SQL injection",
            "high",
            "A database query appears to be built through string interpolation or concatenation.",
            "Untrusted input could alter the intended database query.",
            "Use parameterized queries with bound values.",
            "Replace dynamic query construction with the database driver's parameter-binding API.",
        ),
        _Rule(
            "CODE-002",
            re.compile(r"\b(?:os\.system|subprocess\.(?:run|call|popen)).*(?:shell\s*=\s*True|[\"'])", re.IGNORECASE),
            "Potential command injection",
            "high",
            "A system command invocation may combine application data with a shell command.",
            "Untrusted input could be interpreted as command syntax.",
            "Use fixed executables and argument lists with shell disabled.",
            "Avoid shell invocation; validate allowlisted arguments before process execution.",
        ),
        _Rule(
            "CODE-003",
            re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
            "Dynamic code execution",
            "high",
            "The code evaluates a dynamically supplied expression or statement.",
            "Untrusted content could execute with application privileges.",
            "Use a purpose-built parser or an allowlisted mapping of supported operations.",
            "Remove dynamic evaluation of untrusted input.",
        ),
        _Rule(
            "CODE-004",
            re.compile(r"\b(?:pickle|yaml)\.(?:load|loads)\s*\(", re.IGNORECASE),
            "Unsafe deserialization",
            "high",
            "The code deserializes data using a format that can be unsafe for untrusted inputs.",
            "Crafted data may cause unexpected object construction or code execution.",
            "Use JSON or a safe loader with a validated schema.",
            "Do not deserialize untrusted content with unsafe loaders.",
        ),
        _Rule(
            "CODE-005",
            re.compile(r"\b(?:password|api[_-]?key|secret|token)\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE),
            "Hard-coded secret",
            "medium",
            "A credential-like value appears directly in source code.",
            "Source exposure can disclose reusable credentials.",
            "Load secrets from a managed secret store or environment at runtime.",
            "Rotate the exposed value and remove it from source and version history.",
        ),
        _Rule(
            "CODE-006",
            re.compile(r"\b(?:md5|sha1)\s*\(", re.IGNORECASE),
            "Weak cryptographic hash",
            "medium",
            "The code uses a legacy hash function.",
            "Legacy hashes are not suitable for password storage or collision-resistant integrity checks.",
            "Use an approved password-hashing function or SHA-256+ for non-password integrity needs.",
            "Select modern cryptography appropriate to the security objective.",
        ),
    )

    def analyze(self, code: str, *, file_name: str = "pasted-code") -> tuple[CodeFinding, ...]:
        """Return all recognized findings, preserving source line locations."""
        if not code.strip():
            raise ValueError("Source code is required for analysis.")
        findings: list[CodeFinding] = []
        for line_number, line in enumerate(code.splitlines(), start=1):
            for rule in self._rules:
                if rule.pattern.search(line):
                    findings.append(
                        CodeFinding(
                            finding_id=rule.finding_id,
                            file=file_name,
                            line_number=line_number,
                            vulnerability=rule.vulnerability,
                            severity=rule.severity,
                            explanation=rule.explanation,
                            security_impact=rule.impact,
                            safer_implementation=rule.safer_implementation,
                            remediation=rule.remediation,
                        )
                    )
        return tuple(findings)
