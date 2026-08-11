"""Streamlit UI for the policy-gated chat workflow."""

import streamlit as st

from core.chatbot import ChatProviderError, ChatService, build_chat_provider
from core.security_policy import SecurityPolicy
from database.database import SessionLocal
from database.repositories import ConversationRepository


def render_chat() -> None:
    """Render history, authorization context, and chat input."""
    st.header("AI Security Chat")
    st.caption("Use only for education, defensive security, forensics, and explicitly authorized labs.")
    authorization_confirmed = st.checkbox("I confirm this is an authorized lab or assessment.", value=False)
    conversation_id = st.session_state.get("conversation_id")

    with SessionLocal() as session:
        repository = ConversationRepository(session)
        conversations = repository.list_conversations()
        new_column, delete_column = st.columns(2)
        if new_column.button("New conversation"):
            st.session_state.conversation_id = None
            st.rerun()
        if conversations:
            selected = st.selectbox(
                "Conversation",
                options=[item.id for item in conversations],
                format_func=lambda item_id: next(item.title for item in conversations if item.id == item_id),
                index=next(
                    (index for index, item in enumerate(conversations) if item.id == conversation_id),
                    0,
                ),
            )
            st.session_state.conversation_id = selected
            conversation_id = selected
            selected_conversation = repository.get_with_messages(selected)
            history = selected_conversation.messages
            if delete_column.button("Delete conversation"):
                repository.delete(selected)
                session.commit()
                st.session_state.conversation_id = None
                st.rerun()
            transcript = "\n\n".join(
                f"## {message.role.title()}\n\n{message.content}" for message in history
            )
            st.download_button(
                "Export conversation",
                data=f"# {selected_conversation.title}\n\n{transcript}\n",
                file_name=f"conversation-{selected}.md",
                mime="text/markdown",
            )
            for message in history:
                with st.chat_message(message.role):
                    st.markdown(message.content)

    if prompt := st.chat_input("Ask a cybersecurity question"):
        with SessionLocal() as session:
            service = ChatService(ConversationRepository(session), SecurityPolicy(), build_chat_provider())
            try:
                result = service.respond(
                    prompt,
                    conversation_id=conversation_id,
                    authorization_confirmed=authorization_confirmed,
                )
            except (ChatProviderError, LookupError) as error:
                st.error(str(error))
                return
            session.commit()
            st.session_state.conversation_id = result.conversation.id
            st.rerun()
