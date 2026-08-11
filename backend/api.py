"""FastAPI application for health checks and policy-gated services."""

from dataclasses import asdict

from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.schemas import (
    ChatRequest,
    ChatResponse,
    CodeAnalysisRequest,
    CodeFindingResponse,
    ConversationExport,
    ConversationMessage,
    ConversationSummary,
    DashboardStatsResponse,
    LabAnalysisRequest,
    LabAnalysisResponse,
    LabFindingResponse,
    LearningTopicResponse,
    PolicyCheckRequest,
    PolicyCheckResponse,
    VulnerabilityAnalysisRequest,
    VulnerabilityAnalysisResponse,
)
from core.chatbot import ChatProviderError, ChatService, build_chat_provider
from core.config import get_settings
from core.logging_config import configure_logging
from core.security_policy import SecurityPolicy
from database.database import get_db_session, initialize_database
from database.repositories import ConversationRepository, DashboardRepository
from modules.ethical_hacking import get_topic, list_topics
from modules.lab_assistant import AuthorizedLabAssistant
from modules.vulnerability_analyzer import VulnerabilityAnalyzer
from modules.code_analyzer import CodeAnalyzer

configure_logging()
settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
policy = SecurityPolicy()


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


@app.post("/api/policy/check", response_model=PolicyCheckResponse)
def check_policy(payload: PolicyCheckRequest) -> PolicyCheckResponse:
    decision = policy.classify(payload.request, authorization_confirmed=payload.authorization_confirmed)
    return PolicyCheckResponse(**asdict(decision))


@app.get("/api/dashboard/stats", response_model=DashboardStatsResponse)
def dashboard_stats(session: Session = Depends(get_db_session)) -> DashboardStatsResponse:
    stats = DashboardRepository().get_statistics(session)
    return DashboardStatsResponse(**asdict(stats))


def get_chat_service(session: Session = Depends(get_db_session)) -> ChatService:
    return ChatService(ConversationRepository(session), policy, build_chat_provider())


@app.post("/api/chat", response_model=ChatResponse)
def chat(
    payload: ChatRequest,
    session: Session = Depends(get_db_session),
    service: ChatService = Depends(get_chat_service),
) -> ChatResponse:
    try:
        result = service.respond(
            payload.content,
            conversation_id=payload.conversation_id,
            authorization_confirmed=payload.authorization_confirmed,
        )
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    except ChatProviderError as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)) from error
    session.commit()
    return ChatResponse(
        conversation_id=result.conversation.id,
        response=result.assistant_message.content,
        classification=result.policy.classification.value,
        allowed=result.policy.allowed,
    )


@app.get("/api/conversations", response_model=list[ConversationSummary])
def conversations(session: Session = Depends(get_db_session)) -> list[ConversationSummary]:
    repository = ConversationRepository(session)
    return [ConversationSummary(id=item.id, title=item.title) for item in repository.list_conversations()]


@app.get("/api/conversations/{conversation_id}/export", response_model=ConversationExport)
def export_conversation(conversation_id: int, session: Session = Depends(get_db_session)) -> ConversationExport:
    try:
        conversation = ConversationRepository(session).get_with_messages(conversation_id)
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    return ConversationExport(
        id=conversation.id,
        title=conversation.title,
        messages=[
            ConversationMessage(
                role=message.role,
                content=message.content,
                classification=message.security_classification,
            )
            for message in conversation.messages
        ],
    )


@app.delete("/api/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_conversation(conversation_id: int, session: Session = Depends(get_db_session)) -> Response:
    repository = ConversationRepository(session)
    try:
        repository.delete(conversation_id)
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/learning/topics", response_model=list[LearningTopicResponse])
def learning_topics() -> list[LearningTopicResponse]:
    return [LearningTopicResponse(**asdict(topic)) for topic in list_topics()]


@app.get("/api/learning/topics/{slug}", response_model=LearningTopicResponse)
def learning_topic(slug: str) -> LearningTopicResponse:
    try:
        return LearningTopicResponse(**asdict(get_topic(slug)))
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error


@app.post("/api/labs/interpret", response_model=LabAnalysisResponse)
def interpret_lab(payload: LabAnalysisRequest) -> LabAnalysisResponse:
    analysis = AuthorizedLabAssistant(policy).interpret(**payload.model_dump())
    return LabAnalysisResponse(
        allowed=analysis.allowed,
        classification=analysis.classification.value,
        summary=analysis.summary,
        findings=tuple(LabFindingResponse(**asdict(finding)) for finding in analysis.findings),
    )


@app.post("/api/vulnerabilities/analyze", response_model=VulnerabilityAnalysisResponse)
def analyze_vulnerability(payload: VulnerabilityAnalysisRequest) -> VulnerabilityAnalysisResponse:
    analysis = VulnerabilityAnalyzer().analyze(**payload.model_dump())
    return VulnerabilityAnalysisResponse(**asdict(analysis))


@app.post("/api/code/analyze", response_model=tuple[CodeFindingResponse, ...])
def analyze_code(payload: CodeAnalysisRequest) -> tuple[CodeFindingResponse, ...]:
    findings = CodeAnalyzer().analyze(payload.code, file_name=payload.file_name)
    return tuple(CodeFindingResponse(**asdict(finding)) for finding in findings)
