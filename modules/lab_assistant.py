"""Interpret supplied results from explicitly authorized security labs."""

from dataclasses import dataclass
import re

from core.security_policy import SecurityClassification, SecurityPolicy


@dataclass(frozen=True, slots=True)
class LabFinding:
    title: str
    severity: str
    evidence: str
    recommendation: str


@dataclass(frozen=True, slots=True)
class LabAnalysis:
    allowed: bool
    classification: SecurityClassification
    summary: str
    findings: tuple[LabFinding, ...]


class AuthorizedLabAssistant:
    """Analyze already-collected text; it never connects to or attacks a target."""

    _open_service = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", re.IGNORECASE | re.MULTILINE)
    _header = re.compile(r"^([A-Za-z-]+):\s*(.+)$", re.MULTILINE)

    def __init__(self, policy: SecurityPolicy | None = None) -> None:
        self._policy = policy or SecurityPolicy()

    def interpret(
        self,
        *,
        lab_name: str,
        target_type: str,
        target: str,
        objective: str,
        results: str,
        authorization_confirmed: bool,
    ) -> LabAnalysis:
        """Interpret supplied lab artifacts only after authorization is confirmed."""
        if not authorization_confirmed:
            return LabAnalysis(
                allowed=False,
                classification=SecurityClassification.HIGH_RISK,
                summary="Explicit authorization is required before target-specific lab guidance is provided.",
                findings=(),
            )
        decision = self._policy.classify(results, authorization_confirmed=True)
        if not decision.allowed:
            return LabAnalysis(
                allowed=False,
                classification=decision.classification,
                summary=f"{decision.reason} {decision.safe_alternative or ''}".strip(),
                findings=(),
            )

        findings = list(self._service_findings(results))
        findings.extend(self._header_findings(results))
        if not findings:
            findings.append(
                LabFinding(
                    title="No recognized indicators",
                    severity="info",
                    evidence="The submitted result format did not contain recognized service or HTTP-header lines.",
                    recommendation="Preserve the original artifact and compare it with the lab's expected baseline.",
                )
            )
        return LabAnalysis(
            allowed=True,
            classification=decision.classification,
            summary=(
                f"Interpreted submitted results for authorized lab '{lab_name}' ({target_type}: {target}). "
                f"Objective: {objective}. No network actions were performed."
            ),
            findings=tuple(findings),
        )

    def _service_findings(self, results: str) -> tuple[LabFinding, ...]:
        return tuple(
            LabFinding(
                title=f"Exposed {protocol.upper()} service",
                severity="low",
                evidence=f"Port {port}/{protocol} is marked open with service label '{service}'.",
                recommendation="Confirm this service is required, reachable only from approved networks, and supported.",
            )
            for port, protocol, service in self._open_service.findall(results)
        )

    def _header_findings(self, results: str) -> tuple[LabFinding, ...]:
        headers = {name.lower(): value for name, value in self._header.findall(results)}
        if not headers:
            return ()
        missing = [
            header
            for header in ("content-security-policy", "x-content-type-options", "strict-transport-security")
            if header not in headers
        ]
        if not missing:
            return ()
        return (
            LabFinding(
                title="Security response headers require review",
                severity="low",
                evidence=f"Submitted headers did not include: {', '.join(missing)}.",
                recommendation="Evaluate appropriate headers against the application architecture and deployment requirements.",
            ),
        )
