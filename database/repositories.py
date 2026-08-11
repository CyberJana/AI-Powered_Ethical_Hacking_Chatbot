"""Small persistence queries used by API and UI layers."""

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from database.models import Conversation, Finding, Investigation, Message, Report


@dataclass(frozen=True, slots=True)
class DashboardStatistics:
    total_conversations: int
    investigations: int
    findings: int
    high_severity_findings: int
    reports_generated: int


class DashboardRepository:
    """Read-only aggregate queries for the dashboard."""

    def get_statistics(self, session: Session) -> DashboardStatistics:
        count = lambda model: session.scalar(select(func.count()).select_from(model)) or 0
        high_severity = session.scalar(
            select(func.count()).select_from(Finding).where(Finding.severity.in_(("high", "critical")))
        ) or 0
        return DashboardStatistics(
            total_conversations=count(Conversation),
            investigations=count(Investigation),
            findings=count(Finding),
            high_severity_findings=high_severity,
            reports_generated=count(Report),
        )


class ConversationRepository:
    """Persistence operations for conversation history and exports."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_or_create(self, conversation_id: int | None, *, title: str) -> Conversation:
        if conversation_id is None:
            conversation = Conversation(title=title)
            self._session.add(conversation)
            self._session.flush()
            return conversation
        conversation = self._session.get(Conversation, conversation_id)
        if conversation is None:
            raise LookupError(f"Conversation {conversation_id} was not found.")
        return conversation

    def add_message(self, conversation: Conversation, *, role: str, content: str, classification: str) -> Message:
        message = Message(
            conversation_id=conversation.id,
            role=role,
            content=content,
            security_classification=classification,
        )
        self._session.add(message)
        self._session.flush()
        return message

    def recent_messages(self, conversation_id: int, *, limit: int) -> list[Message]:
        statement = (
            select(Message)
            .where(Message.conversation_id == conversation_id)
            .order_by(Message.created_at.desc(), Message.id.desc())
            .limit(limit)
        )
        return list(reversed(self._session.scalars(statement).all()))

    def list_conversations(self) -> list[Conversation]:
        return list(
            self._session.scalars(select(Conversation).order_by(Conversation.updated_at.desc(), Conversation.id.desc()))
        )

    def get_with_messages(self, conversation_id: int) -> Conversation:
        statement = (
            select(Conversation)
            .options(selectinload(Conversation.messages))
            .where(Conversation.id == conversation_id)
        )
        conversation = self._session.scalar(statement)
        if conversation is None:
            raise LookupError(f"Conversation {conversation_id} was not found.")
        return conversation

    def delete(self, conversation_id: int) -> None:
        conversation = self.get_with_messages(conversation_id)
        self._session.delete(conversation)
