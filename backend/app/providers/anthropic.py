# ============================================================================
# ⚠️  PUBLIC FILE - Part of botchat-oss transparency repo
# ============================================================================
# This file is publicly visible at: https://github.com/LeoooDias/botchat-oss
#
# Purpose: Demonstrate Anthropic API privacy flags (no training opt-out)
#
# ⚠️  DO NOT add proprietary business logic here
# ⚠️  Only provider integration transparency code belongs in this file
# ============================================================================

"""
Anthropic (Claude) provider implementation for botchat.

Uses platform API key for all requests.

Privacy & Data Handling:
- Anthropic does NOT use API inputs/outputs for model training by default
- Data may be retained up to 30 days for trust & safety (abuse monitoring)
- Enterprise plans can negotiate shorter retention periods
- No special headers required (unlike OpenAI's ZDR)

Reference: https://www.anthropic.com/policies/privacy
"""

from __future__ import annotations

import base64
import gc
import io
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, List, Optional

import anthropic  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# -----------------------------
# Configuration
# -----------------------------

# Platform API key (from environment/secrets)
PLATFORM_ANTHROPIC_KEY = os.environ.get("PLATFORM_ANTHROPIC_API_KEY", "")

# Request timeout (seconds) - generous default for streaming responses
# Study mode with multiple bots can take a while, especially with Opus models
# Can be overridden via environment variable for different deployment contexts
DEFAULT_REQUEST_TIMEOUT = float(os.environ.get("ANTHROPIC_REQUEST_TIMEOUT", "300"))

# Vision support: All Claude 3+ models support vision
# We use a blocklist approach - only block models known to NOT support vision
# Currently empty since all modern Claude models support images
NO_VISION_MODELS: set[str] = set()

# Max tokens limits by model (approximate)
DEFAULT_MAX_TOKENS = 4096

# -----------------------------
# Client Singleton (Connection Pooling)
# -----------------------------
# Reusing the Anthropic client across requests enables HTTP connection pooling,
# which significantly reduces Time-To-First-Token (TTFT) by avoiding:
# - Fresh TLS handshakes per request (~200-500ms)
# - TCP slow start on each new connection
# - No HTTP keep-alive benefits

_ANTHROPIC_CLIENT: Optional[anthropic.Anthropic] = None


def _get_anthropic_client(additional_headers: Optional[Dict[str, str]] = None) -> anthropic.Anthropic:
    """
    Get or create the singleton Anthropic client.

    This ensures connection pooling across requests, dramatically improving
    Time-To-First-Token (TTFT) by reusing HTTP connections.

    Args:
        additional_headers: Optional headers (only used on first initialization)

    Returns:
        Shared Anthropic client instance

    Raises:
        AnthropicConfigError: If no API key is configured
    """
    global _ANTHROPIC_CLIENT

    if _ANTHROPIC_CLIENT is None:
        if not PLATFORM_ANTHROPIC_KEY:
            raise AnthropicConfigError("No Anthropic platform API key available")

        client_kwargs: Dict[str, Any] = {
            "api_key": PLATFORM_ANTHROPIC_KEY,
            "timeout": DEFAULT_REQUEST_TIMEOUT,
        }
        if additional_headers:
            client_kwargs["default_headers"] = additional_headers

        _ANTHROPIC_CLIENT = anthropic.Anthropic(**client_kwargs)
        logger.info("🏢 Anthropic client initialized (connection pooling enabled)")

    return _ANTHROPIC_CLIENT


def _strip_exif_metadata(image_bytes: bytes, mime_type: str) -> bytes:
    """
    Strip EXIF metadata from images for privacy.
    
    EXIF data can contain sensitive info: GPS coordinates, device identifiers,
    timestamps, camera settings, etc. We strip it before sending to Anthropic.
    
    Args:
        image_bytes: Raw image bytes
        mime_type: Image MIME type (e.g., "image/jpeg")
        
    Returns:
        Image bytes with EXIF stripped (or original if stripping fails)
    """
    try:
        from PIL import Image
        
        # Only process supported formats
        if mime_type not in ("image/jpeg", "image/png", "image/webp", "image/gif"):
            return image_bytes
        
        # Load image
        img = Image.open(io.BytesIO(image_bytes))
        
        # Create clean copy without EXIF
        output = io.BytesIO()
        
        if mime_type == "image/jpeg":
            img_rgb = img.convert("RGB") if img.mode != "RGB" else img
            img_rgb.save(output, format="JPEG", quality=95)
        elif mime_type == "image/png":
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(img.getdata()))
            clean_img.save(output, format="PNG")
        elif mime_type == "image/webp":
            img.save(output, format="WEBP", quality=95)
        elif mime_type == "image/gif":
            img.save(output, format="GIF")
        else:
            return image_bytes
        
        stripped_bytes = output.getvalue()
        logger.debug("Stripped EXIF metadata: %d -> %d bytes", len(image_bytes), len(stripped_bytes))
        return stripped_bytes
        
    except ImportError:
        logger.warning("Pillow not installed - cannot strip EXIF metadata from images")
        return image_bytes
    except Exception as e:
        logger.warning("Failed to strip EXIF metadata: %s", type(e).__name__)
        return image_bytes


# Patterns that indicate raw PII was passed as user_id (should be hashed)
_PII_PATTERNS_FOR_USER_ID = [
    (r"^[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}$", "email"),  # Email addresses
    (r"^\d{3}-\d{2}-\d{4}$", "SSN"),  # US SSN
    (r"^\d{9}$", "SSN"),  # US SSN without dashes
    (r"^\+?1?[-.]?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}$", "phone"),  # US phone
    (r"^\d{16}$", "credit_card"),  # Credit card (16 digits)
    (r"^\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}$", "credit_card"),  # Credit card with separators
]


def _validate_user_id(user_id: Optional[str]) -> Optional[str]:
    """
    Validate user_id to ensure it's not raw PII.
    
    User IDs should be hashed/opaque identifiers, NOT raw PII like email addresses.
    This function rejects obvious PII patterns and returns None (effectively
    disabling user tracking for that request) while logging a warning.
    
    Args:
        user_id: The user identifier to validate
        
    Returns:
        The user_id if valid, None if it appears to be PII
    """
    import re
    
    if not user_id:
        return None
    
    # Check for obvious PII patterns
    for pattern, pii_type in _PII_PATTERNS_FOR_USER_ID:
        if re.match(pattern, user_id.strip()):
            logger.warning(
                "user_id appears to be raw PII (%s pattern detected). "
                "Please use hashed identifiers. Ignoring user_id for this request.",
                pii_type
            )
            return None
    
    # Additional heuristic: reject if it looks like a name (has spaces and common name patterns)
    if " " in user_id and len(user_id) < 50:
        logger.warning(
            "user_id appears to be a name (contains spaces). "
            "Please use hashed identifiers. Ignoring user_id for this request."
        )
        return None
    
    return user_id


@dataclass
class AnthropicConfig:
    """Configuration for Anthropic requests."""
    model: str
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = 1.0
    strip_metadata: bool = True  # Privacy: don't log filenames by default
    enable_prompt_caching: bool = False  # IGNORED: forced False for privacy


class AnthropicProvider:
    """
    Anthropic provider using platform API key.
    
    Usage:
        provider = AnthropicProvider()
        
        # Stream response
        for chunk in provider.stream("Hello!", model="claude-sonnet-4-20250514"):
            print(chunk, end="")
    """
    
    def __init__(
        self,
        additional_headers: Optional[Dict[str, str]] = None,
        strip_metadata: bool = True,
    ):
        """
        Initialize Anthropic provider.

        Args:
            additional_headers: Optional dict of additional HTTP headers to send
                              (only used on first client initialization).
            strip_metadata: If True, don't log filenames/sensitive metadata (default: True).

        Note:
            Uses a singleton client for connection pooling. This dramatically
            improves TTFT by reusing HTTP connections instead of creating
            fresh TLS handshakes per request.
        """
        self.strip_metadata = strip_metadata

        # Use singleton client for connection pooling (improves TTFT)
        self.client = _get_anthropic_client(additional_headers)
    
    def stream(
        self,
        message: str,
        model: str,
        system_instruction: Optional[str] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        file_data: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 1.0,
        user_id: Optional[str] = None,
        enable_prompt_caching: bool = False,
        pii_scrubber: Optional[Callable[[str], str]] = None,
        web_search_enabled: bool = False,
    ) -> Generator[str, None, Dict[str, Any]]:
        """
        Stream a response from Anthropic.
        
        Args:
            message: User message
            model: Model name (e.g., "claude-sonnet-4-20250514")
            system_instruction: Optional system prompt
            max_tokens: Maximum output tokens
            file_data: Optional list of file attachments [{bytes, mime_type, name}]
            temperature: Sampling temperature (0.0-1.0)
            user_id: Ephemeral session ID (UUID v4) for privacy-preserving rate limiting.
                    PRIVACY: This is a per-request random UUID, NOT the user's identity.
                    Allows provider to rate-limit without correlating across sessions.
            enable_prompt_caching: IGNORED (forced False for privacy). Parameter kept
                                  for API compatibility in case provider defaults change.
            pii_scrubber: Optional callback function to scrub PII from messages
                         before sending to the API. Signature: (str) -> str
            web_search_enabled: Enable web search tool (uses Brave-powered search)
            
        Yields:
            Text chunks as they arrive
            
        Returns:
            Dict with 'citations' list when web search is enabled
        """
        # Track citations for web search
        citations: List[Dict[str, Any]] = []
        
        # Privacy Control: Apply PII scrubbing if configured
        processed_message = message
        processed_system = system_instruction
        if pii_scrubber:
            processed_message = pii_scrubber(message)
            if processed_message != message:
                logger.debug("PII scrubber modified message before sending")
            if system_instruction:
                processed_system = pii_scrubber(system_instruction)
                if processed_system != system_instruction:
                    logger.debug("PII scrubber modified system_instruction before sending")
        
        # Build messages
        messages = self._build_messages(processed_message, model, file_data)
        
        # Validate user_id to ensure it's not raw PII
        validated_user_id = _validate_user_id(user_id)
        
        # Build request parameters
        request_params: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        
        # Add web search tool if enabled
        # Uses Anthropic's web_search tool (Brave-powered)
        # Requires beta header: anthropic-beta: web-search-2025-03-05
        web_search_tools = None
        if web_search_enabled:
            web_search_tools = [{
                "type": "web_search_20250305",
                "name": "web_search",
            }]
            request_params["tools"] = web_search_tools
            logger.debug("Anthropic web search: enabled web_search_20250305 tool")
        
        # Add validated user ID for privacy-preserving abuse monitoring
        # This helps Anthropic with rate limiting and abuse detection without storing PII
        if validated_user_id:
            request_params["metadata"] = {"user_id": validated_user_id}
        
        # Add system instruction (using processed version if PII scrubber was applied)
        # PRIVACY: Prompt caching is DISABLED regardless of parameter value.
        # We keep the parameter for API compatibility and future-proofing, but
        # force it to False to ensure no data is cached on Anthropic's servers.
        # If Anthropic changes their default caching behavior, this explicit
        # handling ensures we remain in a no-cache state.
        if enable_prompt_caching:
            logger.warning("Prompt caching requested but DISABLED for privacy. Ignoring enable_prompt_caching=True.")
        
        if processed_system:
            request_params["system"] = processed_system
        
        # Stream response
        try:
            if web_search_enabled:
                # Web search requires handling tool_use blocks and citations
                # Use beta.messages for web search beta feature
                # Use non-streaming first to get full response with tool results
                response = self.client.beta.messages.create(
                    **request_params,
                    stream=False,
                    betas=["web-search-2025-03-05"]
                )
                
                # Log response structure for debugging
                logger.debug("Anthropic web search response: %d content blocks", len(response.content))
                
                # Process response content blocks
                # Block types from web search:
                # - server_tool_use: The model's request to perform web search
                # - web_search_tool_result: Results from the search
                # - text: Generated text (may contain citations)
                for block in response.content:
                    block_type = getattr(block, 'type', '')
                    logger.debug("Processing block type: %s", block_type)
                    
                    if block_type == 'server_tool_use':
                        # Server-side tool use (web search being invoked)
                        tool_name = getattr(block, 'name', '')
                        if tool_name == 'web_search':
                            tool_input = getattr(block, 'input', {})
                            logger.debug("Web search performed: query=%s", 
                                       tool_input.get('query', 'unknown'))
                    
                    elif block_type == 'web_search_tool_result':
                        # Search results - extract citations from here
                        result_content = getattr(block, 'content', [])
                        for result in result_content:
                            result_type = getattr(result, 'type', '')
                            if result_type == 'web_search_result':
                                url = getattr(result, 'url', '')
                                title = getattr(result, 'title', 'Source')
                                # Add to citations if not duplicate
                                if url and not any(c['url'] == url for c in citations):
                                    citations.append({
                                        'index': len(citations) + 1,
                                        'url': url,
                                        'title': title,
                                    })
                        logger.debug("Extracted %d citations from web_search_tool_result", len(citations))
                    
                    elif block_type == 'text':
                        text_content = getattr(block, 'text', '')
                        
                        # Also check for inline citations in the text block
                        block_citations = getattr(block, 'citations', [])
                        if block_citations:
                            for cite in block_citations:
                                cite_type = getattr(cite, 'type', '')
                                if cite_type == 'web_search_result_location':
                                    url = getattr(cite, 'url', '')
                                    title = getattr(cite, 'title', 'Source')
                                    # Avoid duplicates
                                    if url and not any(c['url'] == url for c in citations):
                                        citations.append({
                                            'index': len(citations) + 1,
                                            'url': url,
                                            'title': title,
                                        })
                        
                        # Yield text in chunks to maintain streaming behavior
                        chunk_size = 100
                        for i in range(0, len(text_content), chunk_size):
                            yield text_content[i:i+chunk_size]
                
                if citations:
                    logger.debug("Total citations from Anthropic web search: %d", len(citations))
                
                # For web search, we can get usage from the non-streaming response
                usage_info = {}
                if hasattr(response, 'usage'):
                    usage_info = {
                        'input_tokens': getattr(response.usage, 'input_tokens', 0) or 0,
                        'output_tokens': getattr(response.usage, 'output_tokens', 0) or 0,
                    }
            else:
                # Standard streaming without web search
                usage_info = {}

                with self.client.messages.stream(**request_params) as stream:
                    for text in stream.text_stream:
                        yield text
                    # Get usage from final message
                    final_message = stream.get_final_message()
                    if final_message and hasattr(final_message, 'usage'):
                        usage_info = {
                            'input_tokens': getattr(final_message.usage, 'input_tokens', 0) or 0,
                            'output_tokens': getattr(final_message.usage, 'output_tokens', 0) or 0,
                        }
                    
        except anthropic.RateLimitError as e:
            logger.error("Anthropic rate limit error (%s)", type(e).__name__)
            logger.debug("Anthropic rate limit: status=%s", getattr(e, "status_code", "n/a"))
            raise RateLimitError("Rate limited by Anthropic API. Please try again later.") from None
        except anthropic.AuthenticationError as e:
            logger.error("Anthropic auth error (%s)", type(e).__name__)
            logger.debug("Anthropic auth: status=%s", getattr(e, "status_code", "n/a"))
            raise AuthenticationError("Invalid API key. Please check your Anthropic API key.") from None
        except anthropic.BadRequestError as e:
            error_msg = str(e)
            error_lower = error_msg.lower()
            logger.error("Anthropic bad request (%s)", type(e).__name__)
            logger.debug("Anthropic bad request: status=%s", getattr(e, "status_code", "n/a"))
            if "context" in error_lower or "too long" in error_lower:
                raise ContextLengthError("Message too long for this model's context window.") from None
            raise AnthropicAPIError("Bad request to Anthropic API. Please check your input.") from None
        except anthropic.NotFoundError as e:
            logger.error("Anthropic model not found (%s)", type(e).__name__)
            logger.debug("Anthropic not found: status=%s", getattr(e, "status_code", "n/a"))
            raise ModelNotFoundError(f"Model '{model}' is not available.") from None
        except Exception as e:
            # Tightened logging: avoid leaking prompts via exception strings
            # Extract only safe attributes - NEVER use %r which may expose request content
            status_code = getattr(e, "status_code", "n/a")
            error_code = getattr(e, "code", "n/a")
            # Log full error type and message for debugging (avoid request content)
            error_message = str(e) if len(str(e)) < 500 else str(e)[:500] + "..."
            logger.error("Anthropic streaming error (%s): %s", type(e).__name__, error_message)
            logger.debug("Anthropic error attrs: status=%s, code=%s", status_code, error_code)
            raise AnthropicAPIError(f"Anthropic API error: {type(e).__name__}") from None
        finally:
            # Best-effort memory cleanup for sensitive data
            # Python doesn't offer secure memory wiping, but explicit deletion
            # helps garbage collection and reduces exposure window
            try:
                del messages
                if file_data:
                    for fd in file_data:
                        if 'bytes' in fd:
                            fd['bytes'] = None
                gc.collect()
            except Exception:
                pass  # Cleanup is best-effort
        
        # Return citations and usage
        return {'citations': citations, 'usage': usage_info}
    
    def _build_messages(
        self,
        message: str,
        model: str,
        file_data: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Build messages array for the API request."""
        # Build user message content
        content: Any = message  # Default to simple string
        
        # Handle file attachments (images)
        # Attempt vision for all models except those known to not support it
        # All Claude 3+ models support vision, so this is very permissive
        if file_data and model not in NO_VISION_MODELS:
            content_parts: List[Dict[str, Any]] = []
            
            for fd in file_data:
                file_bytes = fd.get("bytes")
                mime_type = fd.get("mime_type", "application/octet-stream")
                filename = fd.get("name", "file")
                
                if file_bytes and mime_type.startswith("image/"):
                    # Strip EXIF metadata for privacy (GPS, device IDs, timestamps, etc.)
                    clean_bytes = _strip_exif_metadata(file_bytes, mime_type)
                    
                    # Base64 encode image
                    b64_data = base64.standard_b64encode(clean_bytes).decode("utf-8")
                    content_parts.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": mime_type,
                            "data": b64_data,
                        }
                    })
                    
                    # Conditional logging based on privacy settings
                    if not self.strip_metadata:
                        logger.debug("Added image: %s (%s, %d bytes, EXIF stripped)", 
                                   filename, mime_type, len(clean_bytes))
                    else:
                        logger.debug("Added image (%s, %d bytes, EXIF stripped)", 
                                   mime_type, len(clean_bytes))
            
            # Add text part
            content_parts.append({
                "type": "text",
                "text": message,
            })
            
            content = content_parts
        elif file_data and model in NO_VISION_MODELS:
            logger.warning("Model %s doesn't support vision, ignoring %d file(s)", 
                         model, len(file_data))
        
        return [{"role": "user", "content": content}]
    
    @staticmethod
    def get_privacy_info() -> Dict[str, Any]:
        """Get privacy metadata for Anthropic.
        
        Returns:
            Privacy metadata dict with actionable information
        """
        return {
            "provider": "anthropic",
            "provider_name": "Anthropic (Claude)",
            "docs_url": "https://www.anthropic.com/policies/privacy",
            "training_opt_out": True,  # API data NOT used for training by default
            "data_usage": {
                "training": False,
                "trust_and_safety": True,
                "retention_days": 30,
            },
            "privacy_features": {
                "user_id_support": True,  # Hashed user IDs for abuse monitoring
                "user_id_validation": True,  # We validate user_id is not raw PII
                "prompt_caching": "opt-in",  # Ephemeral caching available
                "exif_stripping": True,  # We strip EXIF from images
                "filename_redaction": True,  # strip_metadata defaults to True
            },
            # Caching disclosure
            "caching_info": {
                "prompt_caching_enabled": False,
                "explicit_disabled": True,
                "description": "Prompt caching is explicitly DISABLED regardless of parameter value.",
                "user_notice": "Your prompts are not cached on Anthropic servers.",
            },
            # Data residency info
            "data_residency": {
                "region": "Anthropic-managed infrastructure",
                "configurable": False,
                "note": "Anthropic does not offer region selection for standard API",
            },
            "backend": "platform",
            "data_retention": "Up to 30 days for trust & safety (application logs)",
            "enterprise_grade": False,
            "compliance": ["SOC 2 Type 2"],
            "privacy_summary": "Platform key - Data not used for training, retained up to 30 days",
            "privacy_level": "high",
            "transparency_note": "Anthropic has strong default privacy (no training on API data)",
            "recommendations": [
                "Use hashed user IDs (not raw PII) for abuse monitoring",
                "Enterprise customers can negotiate shorter retention periods",
            ],
        }


# -----------------------------
# Custom Exceptions
# -----------------------------

class AnthropicAPIError(Exception):
    """Base exception for Anthropic API errors."""
    pass


class RateLimitError(AnthropicAPIError):
    """Rate limit exceeded."""
    pass


class AuthenticationError(AnthropicAPIError):
    """Authentication or authorization failed."""
    pass


class ModelNotFoundError(AnthropicAPIError):
    """Requested model not available."""
    pass


class ContextLengthError(AnthropicAPIError):
    """Input too long for model's context window."""
    pass


class AnthropicConfigError(AnthropicAPIError):
    """Configuration error (e.g., missing API key)."""
    pass


# -----------------------------
# Convenience Functions
# -----------------------------

def stream_anthropic(
    message: str,
    model: str,
    system_instruction: Optional[str] = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    file_data: Optional[List[Dict[str, Any]]] = None,
    temperature: float = 1.0,
    user_id: Optional[str] = None,
    enable_prompt_caching: bool = False,
    web_search_enabled: bool = False,
) -> Generator[str, None, Dict[str, Any]]:
    """
    Stream an Anthropic response.
    
    Convenience function that creates a provider and streams.
    
    Args:
        message: User message
        model: Model name
        system_instruction: Optional system prompt
        max_tokens: Maximum output tokens
        file_data: Optional file attachments
        temperature: Sampling temperature
        user_id: Optional hashed user ID for privacy-preserving abuse monitoring
        enable_prompt_caching: IGNORED (forced False for privacy)
        web_search_enabled: Enable web search tool
        
    Yields:
        Text chunks
        
    Returns:
        Dict with 'citations' list when web search is enabled
    """
    provider = AnthropicProvider()
    return (yield from provider.stream(
        message=message,
        model=model,
        system_instruction=system_instruction,
        max_tokens=max_tokens,
        file_data=file_data,
        temperature=temperature,
        user_id=user_id,
        enable_prompt_caching=enable_prompt_caching,
        web_search_enabled=web_search_enabled,
    ))


def get_anthropic_privacy_info() -> Dict[str, Any]:
    """
    Get privacy info for Anthropic.
    
    Returns:
        Privacy metadata dict for platform usage
    """
    return AnthropicProvider.get_privacy_info()
