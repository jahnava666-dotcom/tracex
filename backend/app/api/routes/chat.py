from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from ...services.ai_chat_service import process_chat_message, SESSION_HISTORIES

router = APIRouter(tags=["TRACE-X Assistant Chat"])

class ChatRequest(BaseModel):
    message: str = Field(..., description="User query or investigation question")
    conversation_id: Optional[str] = Field("default-session", description="Session or conversation identifier")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional page context or active case telemetry")

class ClearChatRequest(BaseModel):
    conversation_id: Optional[str] = "default-session"

@router.post("/chat")
async def chat_endpoint(payload: ChatRequest):
    """
    TRACE-X Assistant Natural Language Chat Endpoint.
    Analyzes intent, evaluates cybersecurity context, queries modular AI LLM or domain expert engine,
    and returns authoritative forensic answers with interactive action suggestions.
    """
    if not payload.message or not payload.message.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message cannot be empty."
        )

    try:
        result = await process_chat_message(
            message=payload.message.strip(),
            conversation_id=payload.conversation_id,
            context=payload.context
        )
        return result
    except Exception as err:
        return {
            "response": (
                "An unexpected processing exception occurred while analyzing your query. "
                "Please verify your question or consult the TRACE-X Investigations dashboard."
            ),
            "conversation_id": payload.conversation_id,
            "intent": "general_cybersecurity",
            "topic": "error_handling",
            "confidence": 0.0,
            "mode": "fallback_error",
            "suggested_questions": ["How do I analyze an email?", "Where can I find my cases?"],
            "actions": [{"label": "Open Dashboard", "action": "navigate_dashboard"}],
            "error": str(err)
        }

@router.post("/chat/clear")
def clear_chat_history(payload: ClearChatRequest):
    """Clear in-memory session history for a conversation ID."""
    conv_id = payload.conversation_id or "default-session"
    if conv_id in SESSION_HISTORIES:
        SESSION_HISTORIES[conv_id] = []
    return {"status": "cleared", "conversation_id": conv_id}
