"""API request and response contracts."""

from pydantic import BaseModel, Field, model_validator


class PolicyCheckRequest(BaseModel):
    request: str = Field(min_length=1, max_length=10_000)
    authorization_confirmed: bool = False


class PolicyCheckResponse(BaseModel):
    classification: str
    allowed: bool
    reason: str
    safe_alternative: str | None = None


class DashboardStatsResponse(BaseModel):
    total_conversations: int
    investigations: int
    findings: int
    high_severity_findings: int
    reports_generated: int


class ChatRequest(BaseModel):
    content: str = Field(min_length=1, max_length=10_000)
    conversation_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False


class ChatResponse(BaseModel):
    conversation_id: int
    response: str
    classification: str
    allowed: bool


class ConversationSummary(BaseModel):
    id: int
    title: str


class ConversationMessage(BaseModel):
    role: str
    content: str
    classification: str


class ConversationExport(BaseModel):
    id: int
    title: str
    messages: list[ConversationMessage]


class LearningTopicResponse(BaseModel):
    slug: str
    category: str
    title: str
    definition: str
    objective: str
    theory: str
    authorized_lab_example: str
    detection_methodology: str
    mitigation: str
    interview_questions: tuple[str, ...]
    practice_questions: tuple[str, ...]


class LabAnalysisRequest(BaseModel):
    lab_name: str = Field(min_length=1, max_length=120)
    target_type: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=253)
    objective: str = Field(min_length=1, max_length=300)
    results: str = Field(min_length=1, max_length=20_000)
    authorization_confirmed: bool


class LabFindingResponse(BaseModel):
    title: str
    severity: str
    evidence: str
    recommendation: str


class LabAnalysisResponse(BaseModel):
    allowed: bool
    classification: str
    summary: str
    findings: tuple[LabFindingResponse, ...]


class VulnerabilityAnalysisRequest(BaseModel):
    cve_id: str | None = Field(default=None, max_length=30)
    description: str | None = Field(default=None, max_length=10_000)
    software_name: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=100)
    scanner_finding: str | None = Field(default=None, max_length=10_000)

    @model_validator(mode="after")
    def requires_evidence(self) -> "VulnerabilityAnalysisRequest":
        if not any((self.cve_id, self.description, self.scanner_finding)):
            raise ValueError("Provide a CVE ID, vulnerability description, or scanner finding.")
        return self


class VulnerabilityAnalysisResponse(BaseModel):
    vulnerability_name: str
    description: str
    severity: str
    cwe: str
    impact: str
    affected_component: str
    detection_guidance: str
    remediation: str
    references: tuple[str, ...]
    risk_explanation: str


class CodeAnalysisRequest(BaseModel):
    code: str = Field(min_length=1, max_length=10 * 1024 * 1024)
    file_name: str = Field(default="pasted-code", min_length=1, max_length=255)


class CodeFindingResponse(BaseModel):
    finding_id: str
    file: str
    line_number: int
    vulnerability: str
    severity: str
    explanation: str
    security_impact: str
    safer_implementation: str
    remediation: str
