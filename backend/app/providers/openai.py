"""
OpenAI provider implementation for botchat.

Uses platform API key for all requests.

Privacy & Data Handling:
- ZDR (Zero Data Retention) header is always sent via X-OpenAI-No-Store
- IMPORTANT: ZDR is only honored for orgs with formal enterprise agreements
- Platform usage: botchat does NOT have ZDR agreement (data retained up to 30 days)

Storage & Caching Policy:
- store=False: Explicitly disabled on every request (prevents distillation/evals storage)
- prompt_cache_key: NOT set (no prompt caching)
- prompt_cache_retention: NOT set (no extended cache TTL)

Transparency is key - we communicate these limitations clearly to users.
"""

from __future__ import annotations

import base64
import gc
import io
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generator, List, Optional

from openai import OpenAI, Stream  # type: ignore[import-untyped]
from openai.types.chat import ChatCompletionChunk  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# -----------------------------
# Configuration
# -----------------------------

# Platform API key (from environment/secrets)
PLATFORM_OPENAI_KEY = os.environ.get("PLATFORM_OPENAI_API_KEY", "")

# Request timeout (seconds) - generous default for streaming responses
# Can be overridden via environment variable for different deployment contexts
DEFAULT_REQUEST_TIMEOUT = float(os.environ.get("OPENAI_REQUEST_TIMEOUT", "120"))

# Supported models (as of Dec 2025)
SUPPORTED_MODELS = {
    # GPT-4 family
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4",
    # GPT-4.1 family (2025)
    "gpt-4.1",
    "gpt-4.1-mini",
    "gpt-4.1-nano",
    # o1/o3 reasoning models
    "o1",
    "o1-mini",
    "o1-preview",
    "o3-mini",
    # Legacy
    "gpt-3.5-turbo",
}

# Models that support vision (image inputs)
# Most modern GPT models support vision - this list is for explicit confirmation
# Models not listed here will still attempt vision if image is provided
VISION_MODELS = {
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4.1",
    "gpt-4.1-mini",
    "o1",
    # GPT-5 family (2025-2026)
    "gpt-5",
    "gpt-5.1",
    "gpt-5.2",
    "gpt-5-mini",
}

# Models known to NOT support vision
NO_VISION_MODELS = {
    "gpt-3.5-turbo",
    "gpt-4",  # base gpt-4 without vision
    "o1-mini",
    "o1-preview",
    "o3-mini",
}

# Models that DON'T support system instructions (reasoning models)
NO_SYSTEM_INSTRUCTION_MODELS = {
    "o1",
    "o1-mini",
    "o1-preview",
    "o3-mini",
}


def _strip_exif_metadata(image_bytes: bytes, mime_type: str) -> bytes:
    """
    Strip EXIF metadata from images for privacy.
    
    EXIF data can contain sensitive info: GPS coordinates, device identifiers,
    timestamps, camera settings, etc. We strip it before sending to OpenAI.
    
    Args:
        image_bytes: Raw image bytes
        mime_type: Image MIME type (e.g., "image/jpeg")
        
    Returns:
        Image bytes with EXIF stripped (or original if stripping fails)
    """
    try:
        from PIL import Image
        
        # Only process supported formats
        if mime_type not in ("image/jpeg", "image/png", "image/webp", "image/heic"):
            return image_bytes
        
        # Load image
        img = Image.open(io.BytesIO(image_bytes))
        
        # Create clean copy without EXIF
        # For JPEG/WebP, re-encoding drops EXIF; for PNG, we copy pixel data only
        output = io.BytesIO()
        
        # Determine output format
        if mime_type == "image/jpeg":
            # Re-encode as JPEG without EXIF (quality 95 to minimize loss)
            img_rgb = img.convert("RGB") if img.mode != "RGB" else img
            img_rgb.save(output, format="JPEG", quality=95)
        elif mime_type == "image/png":
            # PNG: copy to new image to strip metadata chunks
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(img.getdata()))
            clean_img.save(output, format="PNG")
        elif mime_type == "image/webp":
            img.save(output, format="WEBP", quality=95)
        else:
            # Unsupported format, return original
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
class OpenAIConfig:
    """Configuration for OpenAI requests."""
    model: str
    max_tokens: int = 4000
    temperature: float = 1.0
    top_p: float = 1.0


class OpenAIProvider:
    """
    OpenAI provider using platform API key.
    
    Usage:
        provider = OpenAIProvider()
        
        # Stream response
        for chunk in provider.stream("Hello!", model="gpt-4o"):
            print(chunk, end="")
    """
    
    def __init__(self, strip_metadata: bool = True):
        """
        Initialize OpenAI provider.
        
        Args:
            strip_metadata: If True, don't log filenames/sensitive metadata (default: True).
        """
        self.api_key = PLATFORM_OPENAI_KEY
        self.strip_metadata = strip_metadata
        
        if not self.api_key:
            raise OpenAIConfigError("No OpenAI platform API key available")
        
        # Create client with ZDR header and minimized SDK telemetry
        # NOTE: X-OpenAI-No-Store is only honored for orgs with formal ZDR agreements
        # NOTE: X-Stainless-* headers are SDK telemetry - we suppress them for privacy
        self.client = OpenAI(
            api_key=self.api_key,
            timeout=DEFAULT_REQUEST_TIMEOUT,  # Explicit timeout for reliability
            default_headers={
                "X-OpenAI-No-Store": "true",  # Request ZDR (best-effort, not guaranteed)
                # Minimize SDK telemetry headers (privacy-forward)
                "X-Stainless-OS": "private",
                "X-Stainless-Arch": "private",
                "X-Stainless-Runtime": "private",
                "X-Stainless-Runtime-Version": "private",
                "X-Stainless-Package-Version": "private",
                "X-Stainless-Lang": "private",
            }
        )
        logger.info("🏢 Using botchat's OpenAI platform API key")
    
    def stream(
        self,
        message: str,
        model: str,
        system_instruction: Optional[str] = None,
        max_tokens: int = 4000,
        file_data: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 1.0,
        user_id: Optional[str] = None,
        pii_scrubber: Optional[Callable[[str], str]] = None,
        web_search_enabled: bool = False,
    ) -> Generator[str, None, Dict[str, Any]]:
        """
        Stream a response from OpenAI.
        
        Args:
            message: User message
            model: Model name (e.g., "gpt-4o")
            system_instruction: Optional system prompt (ignored for o1/o3 models)
            max_tokens: Maximum output tokens
            file_data: Optional list of file attachments [{bytes, mime_type, name}]
            temperature: Sampling temperature (0.0-2.0)
            user_id: Ephemeral session ID (UUID v4) for privacy-preserving rate limiting.
                    PRIVACY: This is a per-request random UUID, NOT the user's identity.
                    Allows provider to rate-limit without correlating across sessions.
                    Sent as safety_identifier to OpenAI.
            pii_scrubber: Optional callback function to scrub PII from messages
                         before sending to the API. Signature: (str) -> str
            web_search_enabled: Enable web search tool (uses Responses API)
            
        Yields:
            Text chunks as they arrive
            
        Returns:
            Dict with 'citations' list when web search is enabled
        """
        # Validate model
        if model not in SUPPORTED_MODELS:
            logger.warning("Model '%s' not in supported list, attempting anyway", model)
        
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
        messages = self._build_messages(processed_message, model, processed_system, file_data)
        
        # Validate user_id to ensure it's not raw PII
        validated_user_id = _validate_user_id(user_id)
        
        # Track citations for web search
        citations: List[Dict[str, Any]] = []
        
        # Web search uses Responses API (different from Chat Completions)
        if web_search_enabled:
            return (yield from self._stream_with_web_search(
                processed_message, model, processed_system, max_tokens, 
                temperature, validated_user_id
            ))
        
        # Build messages for Chat Completions API
        messages = self._build_messages(processed_message, model, processed_system, file_data)
        
        # Build request parameters
        # IMPORTANT: store=False disables OpenAI's request/response storage
        # This is the primary privacy control (X-OpenAI-No-Store is best-effort only)
        request_params: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": True,
            "store": False,  # Disable application state storage
        }
        
        # PRIVACY: Explicitly disable prompt caching by not setting prompt_cache_key
        # OpenAI's prompt caching requires a cache key to be set; without it, no caching occurs.
        # We intentionally do NOT set prompt_cache_key or prompt_cache_retention.
        # If OpenAI changes defaults in the future, we should revisit this.
        
        # Add validated user ID for privacy-preserving abuse monitoring
        # This helps OpenAI with abuse detection without storing PII
        if validated_user_id:
            request_params["safety_identifier"] = validated_user_id
        
        # Add optional parameters (some models don't support all params)
        if model not in NO_SYSTEM_INSTRUCTION_MODELS:
            request_params["max_completion_tokens"] = max_tokens
            request_params["temperature"] = temperature
        else:
            # Reasoning models use max_completion_tokens but not temperature
            request_params["max_completion_tokens"] = max_tokens
        
        # Stream response
        try:
            response_stream: Stream[ChatCompletionChunk] = self.client.chat.completions.create(**request_params)  # type: ignore[assignment]
            
            for chunk in response_stream:  # pyright: ignore[reportUnknownVariableType]
                if chunk.choices and chunk.choices[0].delta.content:  # pyright: ignore[reportUnknownMemberType]
                    yield chunk.choices[0].delta.content  # pyright: ignore[reportUnknownMemberType]
                    
        except Exception as e:
            # Tightened logging: avoid leaking prompts via exception strings
            # Extract only safe attributes - NEVER use %r which may expose request content
            status_code = getattr(e, "status_code", "n/a")
            error_code = getattr(e, "code", "n/a")
            error_type = getattr(e, "type", "n/a")
            logger.error("OpenAI streaming error (%s, status=%s)", type(e).__name__, status_code)
            logger.debug("OpenAI error attrs: code=%s, type=%s", error_code, error_type)
            
            error_msg = str(e)
            error_lower = error_msg.lower()
            
            # Provide user-friendly error messages (sanitized - no raw error in user output)
            # Use 'from None' to suppress exception context and prevent traceback leakage
            if "429" in error_msg or "rate" in error_lower:
                raise RateLimitError("Rate limited by OpenAI API. Please try again later.") from None
            elif "401" in error_msg or "invalid_api_key" in error_lower:
                raise AuthenticationError("Invalid API key. Please check your OpenAI API key.") from None
            elif "403" in error_msg or "permission" in error_lower:
                raise AuthenticationError("Permission denied. Your API key may lack required permissions.") from None
            elif "model" in error_lower and ("not found" in error_lower or "does not exist" in error_lower):
                raise ModelNotFoundError(f"Model '{model}' is not available.") from None
            elif "context_length" in error_lower or "maximum context" in error_lower:
                raise ContextLengthError("Message too long for this model's context window.") from None
            else:
                raise OpenAIAPIError("OpenAI API error. Please try again.") from None
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
        
        # Return empty citations for non-web-search requests
        return {'citations': citations}
    
    def _stream_with_web_search(
        self,
        message: str,
        model: str,
        system_instruction: Optional[str],
        max_tokens: int,
        temperature: float,
        user_id: Optional[str],
    ) -> Generator[str, None, Dict[str, Any]]:
        """
        Stream a response with web search using OpenAI Responses API.
        
        The Responses API supports the web_search_preview tool, which enables
        the model to search the web and cite sources.
        
        Args:
            message: User message
            model: Model name
            system_instruction: Optional system prompt
            max_tokens: Maximum output tokens
            temperature: Sampling temperature
            user_id: Optional hashed user ID
            
        Yields:
            Text chunks
            
        Returns:
            Dict with 'citations' list
        """
        citations: List[Dict[str, Any]] = []
        
        try:
            # Build input with system instruction if provided
            input_content: Any = message
            if system_instruction and model not in NO_SYSTEM_INSTRUCTION_MODELS:
                input_content = [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": message},
                ]
            elif system_instruction:
                # For reasoning models, prepend system instruction
                input_content = f"[Instructions]\n{system_instruction}\n\n[User Message]\n{message}"
            
            # Build request parameters for Responses API
            request_params: Dict[str, Any] = {
                "model": model,
                "input": input_content,
                "tools": [{"type": "web_search_preview"}],
                "stream": True,
                "store": False,  # Privacy: disable storage
            }
            
            # Add optional parameters
            if model not in NO_SYSTEM_INSTRUCTION_MODELS:
                request_params["max_output_tokens"] = max_tokens
                request_params["temperature"] = temperature
            else:
                request_params["max_output_tokens"] = max_tokens
            
            if user_id:
                request_params["user"] = user_id
            
            logger.debug("OpenAI web search: using Responses API with web_search_preview tool")
            
            # Stream using Responses API
            # Note: responses.create returns a different structure than chat.completions
            response_stream = self.client.responses.create(**request_params)
            
            # Track text content and annotations from output items
            collected_text: List[str] = []
            collected_annotations: List[Dict[str, Any]] = []
            
            for event in response_stream:
                # Handle different event types from Responses API streaming
                event_type = getattr(event, 'type', '')
                
                if event_type == 'response.output_text.delta':
                    # Text chunk from the model
                    delta = getattr(event, 'delta', '')
                    if delta:
                        collected_text.append(delta)
                        yield delta
                        
                elif event_type == 'response.output_text.done':
                    # Final text with annotations
                    text_obj = getattr(event, 'text', None)
                    if text_obj:
                        annotations = getattr(text_obj, 'annotations', [])
                        for ann in annotations:
                            if getattr(ann, 'type', '') == 'url_citation':
                                collected_annotations.append({
                                    'url': getattr(ann, 'url', ''),
                                    'title': getattr(ann, 'title', 'Source'),
                                    'start_index': getattr(ann, 'start_index', 0),
                                    'end_index': getattr(ann, 'end_index', 0),
                                })
                                
                elif event_type == 'response.done':
                    # Response complete - extract any remaining annotations
                    response_obj = getattr(event, 'response', None)
                    if response_obj:
                        output_items = getattr(response_obj, 'output', [])
                        for item in output_items:
                            if getattr(item, 'type', '') == 'message':
                                content_list = getattr(item, 'content', [])
                                for content in content_list:
                                    if getattr(content, 'type', '') == 'output_text':
                                        for ann in getattr(content, 'annotations', []):
                                            if getattr(ann, 'type', '') == 'url_citation':
                                                # Avoid duplicates
                                                url = getattr(ann, 'url', '')
                                                if not any(c['url'] == url for c in collected_annotations):
                                                    collected_annotations.append({
                                                        'url': url,
                                                        'title': getattr(ann, 'title', 'Source'),
                                                        'start_index': getattr(ann, 'start_index', 0),
                                                        'end_index': getattr(ann, 'end_index', 0),
                                                    })
            
            # Build citations from collected annotations
            for idx, ann in enumerate(collected_annotations):
                citations.append({
                    'index': idx + 1,
                    'url': ann['url'],
                    'title': ann['title'],
                })
            
            if citations:
                logger.debug("Extracted %d citations from OpenAI web search", len(citations))
                
        except Exception as e:
            status_code = getattr(e, "status_code", "n/a")
            error_code = getattr(e, "code", "n/a")
            logger.error("OpenAI web search error (%s, status=%s)", type(e).__name__, status_code)
            
            error_msg = str(e)
            error_lower = error_msg.lower()
            
            if "429" in error_msg or "rate" in error_lower:
                raise RateLimitError("Rate limited by OpenAI API. Please try again later.") from None
            elif "401" in error_msg or "invalid_api_key" in error_lower:
                raise AuthenticationError("Invalid API key. Please check your OpenAI API key.") from None
            elif "403" in error_msg or "permission" in error_lower:
                raise AuthenticationError("Permission denied. Your API key may lack required permissions.") from None
            elif "responses" in error_lower or "not supported" in error_lower:
                raise OpenAIAPIError("Web search requires a compatible model and API version.") from None
            else:
                raise OpenAIAPIError("OpenAI API error. Please try again.") from None
        
        return {'citations': citations}
    
    def _build_messages(
        self,
        message: str,
        model: str,
        system_instruction: Optional[str] = None,
        file_data: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Build messages array for the API request."""
        messages: List[Dict[str, Any]] = []
        
        # Add system message (if supported by model)
        if system_instruction and model not in NO_SYSTEM_INSTRUCTION_MODELS:
            messages.append({
                "role": "system",
                "content": system_instruction,
            })
        elif system_instruction and model in NO_SYSTEM_INSTRUCTION_MODELS:
            # For reasoning models, prepend system instruction to user message
            logger.debug("Model %s doesn't support system instructions, prepending to user message", model)
            message = f"[Instructions]\n{system_instruction}\n\n[User Message]\n{message}"
        
        # Build user message content
        user_content: Any = message  # Default to simple string
        
        # Handle file attachments (images)
        # Attempt vision for all models except those known to not support it
        # This is more future-proof than maintaining an allowlist
        if file_data and model not in NO_VISION_MODELS:
            # Multi-part content for vision
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
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{mime_type};base64,{b64_data}",
                            "detail": "auto",  # Let OpenAI choose resolution
                        }
                    })
                    
                    # Conditional logging based on privacy settings
                    if not self.strip_metadata:
                        logger.debug("Added image to request: %s (%s, %d bytes, EXIF stripped)", 
                                   filename, mime_type, len(clean_bytes))
                    else:
                        logger.debug("Added image (%s, %d bytes, EXIF stripped)",
                                   mime_type, len(clean_bytes))
            
            # Add text part
            content_parts.append({
                "type": "text",
                "text": message,
            })
            
            user_content = content_parts
        elif file_data and model in NO_VISION_MODELS:
            logger.warning("Model %s doesn't support vision, ignoring %d file(s)", 
                         model, len(file_data))
        
        messages.append({
            "role": "user",
            "content": user_content,
        })
        
        return messages
    
    @staticmethod
    def get_privacy_info() -> Dict[str, Any]:
        """Get privacy metadata for OpenAI.
        
        Returns:
            Privacy metadata dict with accurate ZDR information
        """
        return {
            "provider": "openai",
            "provider_name": "OpenAI",
            "docs_url": "https://openai.com/policies/api-data-usage-policies",
            "zdr_header_sent": True,  # We always send X-OpenAI-No-Store
            # Caching disclosure
            "caching_info": {
                "prompt_caching_enabled": False,
                "prompt_cache_key_set": False,
                "description": "Prompt caching is explicitly disabled (no cache key set). store=false prevents request storage.",
                "user_notice": "Your prompts are not cached. store=false is set on every request.",
            },
            # Data residency info
            "data_residency": {
                "region": "OpenAI-managed (US-based infrastructure)",
                "configurable": False,
                "note": "OpenAI does not offer region selection for API requests",
            },
            # Privacy features
            "privacy_features": {
                "exif_stripping": True,  # We strip EXIF from images
                "user_id_validation": True,  # We validate user_id is not raw PII
                "filename_redaction": True,  # strip_metadata defaults to True
            },
            "backend": "platform",
            "data_retention": "Application state/logs retained up to 30 days, then removed",
            "training_opt_out": True,  # API data not used for training
            "zdr_honored": False,  # botchat doesn't have ZDR agreement
            "enterprise_grade": False,
            "compliance": ["SOC 2 Type 2"],
            "privacy_summary": "Platform key - store=false set, data retained up to 30 days (no ZDR agreement)",
            "privacy_level": "medium",
            "transparency_note": "botchat has not applied for OpenAI's ZDR program",
            "store_disabled": True,  # We always set store=false
        }


# -----------------------------
# Custom Exceptions
# -----------------------------

class OpenAIAPIError(Exception):
    """Base exception for OpenAI API errors."""
    pass


class RateLimitError(OpenAIAPIError):
    """Rate limit exceeded."""
    pass


class AuthenticationError(OpenAIAPIError):
    """Authentication or authorization failed."""
    pass


class ModelNotFoundError(OpenAIAPIError):
    """Requested model not available."""
    pass


class ContextLengthError(OpenAIAPIError):
    """Input too long for model's context window."""
    pass


class OpenAIConfigError(OpenAIAPIError):
    """Configuration error (e.g., missing API key)."""
    pass


# -----------------------------
# Convenience Functions
# -----------------------------

def stream_openai(
    message: str,
    model: str,
    system_instruction: Optional[str] = None,
    max_tokens: int = 4000,
    file_data: Optional[List[Dict[str, Any]]] = None,
    temperature: float = 1.0,
    user_id: Optional[str] = None,
    web_search_enabled: bool = False,
) -> Generator[str, None, Dict[str, Any]]:
    """
    Stream an OpenAI response.
    
    Convenience function that creates a provider and streams.
    
    Args:
        message: User message
        model: Model name
        system_instruction: Optional system prompt
        max_tokens: Maximum output tokens
        file_data: Optional file attachments
        temperature: Sampling temperature
        user_id: Optional hashed user ID for privacy-preserving abuse monitoring
        web_search_enabled: Enable web search tool
        
    Yields:
        Text chunks
        
    Returns:
        Dict with 'citations' list when web search is enabled
    """
    provider = OpenAIProvider()
    return (yield from provider.stream(
        message=message,
        model=model,
        system_instruction=system_instruction,
        max_tokens=max_tokens,
        file_data=file_data,
        temperature=temperature,
        user_id=user_id,
        web_search_enabled=web_search_enabled,
    ))


def get_openai_privacy_info() -> Dict[str, Any]:
    """
    Get privacy info for OpenAI.
    
    Returns:
        Privacy metadata dict
    """
    return OpenAIProvider.get_privacy_info()
