"""Provider-independent chat orchestration for safe cybersecurity conversations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.config import Settings, get_settings
from core.prompts import PromptMessage, build_system_prompt, to_provider_messages
from core.security_policy import PolicyDecision, SecurityPolicy
from database.models import Conversation, Message
from database.repositories import ConversationRepository


class ChatProviderError(RuntimeError):
    """Raised when a configured LLM provider cannot generate a response."""


class ChatProvider(Protocol):
    """Minimal contract that allows different LLM vendors to be substituted."""

    def generate(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        """Generate an assistant response from a system prompt and conversation history."""


class DisabledChatProvider:
    """Explicitly rejects chat generation until a provider is configured."""

    def generate(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        raise ChatProviderError(
            "No AI provider is configured. Set LLM_PROVIDER=openai_compatible and the related environment variables."
        )


class OpenAICompatibleProvider:
    """Small HTTP client for OpenAI-compatible chat-completions APIs."""

    def __init__(self, *, api_base: str, api_key: str, model: str) -> None:
        self._endpoint = f"{api_base.rstrip('/')}/chat/completions"
        self._api_key = api_key
        self._model = model

    def generate(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        payload = json.dumps(
            {
                "model": self._model,
                "messages": [{"role": "system", "content": system_prompt}, *messages],
                "temperature": 0.2,
            }
        ).encode("utf-8")
        request = Request(
            self._endpoint,
            data=payload,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            raise ChatProviderError(f"The AI provider returned HTTP {error.code}.") from error
        except URLError as error:
            raise ChatProviderError("The AI provider could not be reached.") from error
        except json.JSONDecodeError as error:
            raise ChatProviderError("The AI provider returned invalid JSON.") from error

        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise ChatProviderError("The AI provider returned an invalid response format.") from error
        if not isinstance(content, str) or not content.strip():
            raise ChatProviderError("The AI provider returned an empty response.")
        return content.strip()


def build_chat_provider(settings: Settings | None = None) -> ChatProvider:
    """Construct the configured provider without embedding credentials in code."""
    settings = settings or get_settings()
    if settings.llm_provider.lower() == "disabled":
        return DisabledChatProvider()
    if settings.llm_provider.lower() == "openai_compatible":
        if not (settings.llm_api_base and settings.llm_api_key and settings.llm_model):
            raise ChatProviderError("LLM_API_BASE, LLM_API_KEY, and LLM_MODEL are required for openai_compatible.")
        return OpenAICompatibleProvider(
            api_base=settings.llm_api_base,
            api_key=settings.llm_api_key,
            model=settings.llm_model,
        )
    raise ChatProviderError(f"Unsupported LLM_PROVIDER: {settings.llm_provider}.")


@dataclass(frozen=True, slots=True)
class ChatResult:
    conversation: Conversation
    assistant_message: Message
    policy: PolicyDecision


class ChatService:
    """Apply policy, persist messages, and delegate safe requests to a provider."""

    def __init__(
        self,
        repository: ConversationRepository,
        policy: SecurityPolicy,
        provider: ChatProvider,
    ) -> None:
        self._repository = repository
        self._policy = policy
        self._provider = provider

    def respond(
        self,
        content: str,
        *,
        conversation_id: int | None = None,
        authorization_confirmed: bool = False,
    ) -> ChatResult:
        decision = self._policy.classify(content, authorization_confirmed=authorization_confirmed)
        conversation = self._repository.get_or_create(conversation_id, title=self._title_for(content))
        self._repository.add_message(conversation, role="user", content=content, classification=decision.classification.value)

        if decision.allowed:
            history = self._repository.recent_messages(conversation.id, limit=16)
            response = self._provider.generate(
                system_prompt=build_system_prompt(decision.classification),
                messages=to_provider_messages(
                    [PromptMessage(role=message.role, content=message.content) for message in history]
                ),
            )
        else:
            response = f"{decision.reason} {decision.safe_alternative or ''}".strip()

        assistant_message = self._repository.add_message(
            conversation,
            role="assistant",
            content=response,
            classification=decision.classification.value,
        )
        return ChatResult(conversation=conversation, assistant_message=assistant_message, policy=decision)

    @staticmethod
    def _title_for(content: str) -> str:
        return content.strip().replace("\n", " ")[:80] or "New conversation"
