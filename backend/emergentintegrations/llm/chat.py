from typing import Optional, AsyncIterator, List
import httpx


class UserMessage:
    def __init__(self, text: str):
        self.text = text


class TextDelta:
    def __init__(self, content: str):
        self.content = content


class StreamDone:
    pass


class LlmChat:
    """Simple mock LLM chat client for emergentintegrations."""
    
    def __init__(
        self,
        api_key: str = "",
        session_id: str = "",
        system_message: str = "",
    ):
        self.api_key = api_key
        self.session_id = session_id
        self.system_message = system_message
        self.model_name = "claude-sonnet-4-5-20250929"
        self.history: List[dict] = []
        if system_message:
            self.history.append({"role": "system", "content": system_message})
    
    def with_model(self, provider: str, model: str):
        self.model_name = model
        return self
    
    async def stream_message(self, user_msg: UserMessage) -> AsyncIterator:
        """Stream a response from the LLM."""
        # Add user message to history
        self.history.append({"role": "user", "content": user_msg.text})
        
        # Mock response - in production this would call the actual LLM API
        mock_response = self._generate_mock_response(user_msg.text)
        
        # Stream the response character by character (simulated)
        full_content = ""
        for char in mock_response:
            full_content += char
            yield TextDelta(content=char)
        
        # Add assistant message to history
        self.history.append({"role": "assistant", "content": full_content})
        yield StreamDone()
    
    def _generate_mock_response(self, user_text: str) -> str:
        """Generate a mock response based on user input."""
        # Simple echo-like response for demo purposes
        if "mood" in user_text.lower() or "day" in user_text.lower():
            return "Thank you for sharing about your day. I'm here to listen and help you reflect. What stood out to you most today?"
        elif "json" in user_text.lower():
            return '{"date": "2025-01-15", "mood": "reflective", "mood_score": 7, "energy_score": 6, "habits": ["+morning walk", "-meditation"], "emotions": ["curious", "thoughtful"], "themes": ["self-reflection"], "wins": ["completed a task"], "challenges": ["staying focused"], "summary": "The user had a reflective day with moments of insight.", "growth_nudge": "Consider setting one small intention for tomorrow."}'
        else:
            return "I hear you. Tell me more about how that made you feel. What patterns do you notice when this happens?"
