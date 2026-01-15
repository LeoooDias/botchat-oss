"""
AI Provider implementations for botchat.

This module provides direct integrations with AI providers,
giving botchat full control over privacy, transparency, and features.

v2.2.0: Gemini via Vertex AI
v2.3.0: OpenAI direct integration
v2.4.0: Anthropic direct integration - all providers native
"""

from app.providers.gemini import (
    GeminiProvider,
    stream_gemini,
    get_gemini_privacy_info,
    GeminiAPIError,
    RateLimitError as GeminiRateLimitError,
)

from app.providers.openai import (
    OpenAIProvider,
    stream_openai,
    get_openai_privacy_info,
    OpenAIAPIError,
    RateLimitError as OpenAIRateLimitError,
    AuthenticationError as OpenAIAuthError,
    ContextLengthError as OpenAIContextLengthError,
)

from app.providers.anthropic import (
    AnthropicProvider,
    stream_anthropic,
    get_anthropic_privacy_info,
    AnthropicAPIError,
    RateLimitError as AnthropicRateLimitError,
    AuthenticationError as AnthropicAuthError,
    ContextLengthError as AnthropicContextLengthError,
)

__all__ = [
    # Gemini
    "GeminiProvider",
    "stream_gemini", 
    "get_gemini_privacy_info",
    "GeminiAPIError",
    "GeminiRateLimitError",
    # OpenAI
    "OpenAIProvider",
    "stream_openai",
    "get_openai_privacy_info",
    "OpenAIAPIError",
    "OpenAIRateLimitError",
    "OpenAIAuthError",
    "OpenAIContextLengthError",
    # Anthropic
    "AnthropicProvider",
    "stream_anthropic",
    "get_anthropic_privacy_info",
    "AnthropicAPIError",
    "AnthropicRateLimitError",
    "AnthropicAuthError",
    "AnthropicContextLengthError",
]
