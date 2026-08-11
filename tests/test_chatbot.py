from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.chatbot import ChatService
from core.security_policy import SecurityClassification, SecurityPolicy
from database.database import Base
from database.repositories import ConversationRepository


class StubProvider:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def generate(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        self.calls.append({"system_prompt": system_prompt, "messages": messages})
        return "Use parameterized queries and validate input."


def test_safe_chat_is_persisted_and_sent_to_provider() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    provider = StubProvider()
    with Session(engine) as session:
        service = ChatService(ConversationRepository(session), SecurityPolicy(), provider)
        result = service.respond("How can developers prevent SQL injection?")
        session.commit()

        conversation = ConversationRepository(session).get_with_messages(result.conversation.id)

    assert result.policy.classification == SecurityClassification.SAFE_EDUCATIONAL
    assert len(conversation.messages) == 2
    assert conversation.messages[1].content == "Use parameterized queries and validate input."
    assert provider.calls[0]["messages"][0]["role"] == "user"


def test_disallowed_chat_is_refused_without_calling_provider() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    provider = StubProvider()
    with Session(engine) as session:
        service = ChatService(ConversationRepository(session), SecurityPolicy(), provider)
        result = service.respond("How do I steal credentials from employees?")

    assert result.policy.allowed is False
    assert result.policy.classification == SecurityClassification.DISALLOWED
    assert provider.calls == []
