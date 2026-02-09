# ============================================================================
# ⚠️  PUBLIC FILE - Part of botchat-oss transparency repo
# ============================================================================
# This file is publicly visible at: https://github.com/LeoooDias/botchat-oss
#
# Purpose: Demonstrate Gemini/Vertex AI privacy configuration
#
# ⚠️  DO NOT add proprietary business logic here
# ⚠️  Only provider integration transparency code belongs in this file
# ============================================================================

"""
Gemini provider implementation for botchat.

Uses Vertex AI (GCP service account authentication) for all requests.

Privacy & Data Handling:
- Vertex AI: Enterprise-grade, data processed in specified region
- Data NOT used for model training

Caching Policy:
- EXPLICIT CACHING: We do NOT use client.caches.create() or cached_content.
  All requests are stateless with no server-side content persistence.
- IMPLICIT CACHING: Google enables this automatically (as of May 2025) for
  cost optimization. There is NO client-side opt-out. Google states this is
  transient and used only for billing optimization, not data retention.
  See: https://ai.google.dev/gemini-api/docs/caching
"""

from __future__ import annotations

import gc
import io
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generator, List, Optional

from google import genai  # type: ignore[import-untyped]
from google.genai import types  # type: ignore[import-untyped]
from google.oauth2 import service_account  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# -----------------------------
# Configuration
# -----------------------------

# GCP project and region for Vertex AI
VERTEX_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "botchat-prod-1228")
VERTEX_REGION = os.environ.get("GOOGLE_CLOUD_REGION", "us-central1")

# Service account credentials (JSON string from Secret Manager)
VERTEX_SERVICE_ACCOUNT_JSON = os.environ.get("VERTEX_AI_SERVICE_ACCOUNT", "")

# Request timeout (seconds) - must be generous for Study mode with large PDFs
# Study mode: 32K output tokens + large PDFs can take 3-5 minutes
# Can be overridden via environment variable for different deployment contexts
DEFAULT_REQUEST_TIMEOUT = float(os.environ.get("GEMINI_REQUEST_TIMEOUT", "600"))

# -----------------------------
# Client Singleton (Connection Pooling)
# -----------------------------
# Reusing the Gemini client across requests enables HTTP connection pooling,
# which significantly reduces Time-To-First-Token (TTFT) by avoiding:
# - Fresh TLS handshakes per request (~200-500ms)
# - TCP slow start on each new connection
# - No HTTP keep-alive benefits

_GEMINI_CLIENT: Optional[genai.Client] = None


def _get_gemini_client() -> genai.Client:
    """
    Get or create the singleton Gemini (Vertex AI) client.

    This ensures connection pooling across requests, dramatically improving
    Time-To-First-Token (TTFT) by reusing HTTP connections.

    Returns:
        Shared Gemini client instance

    Raises:
        RuntimeError: If Vertex AI configuration is invalid
    """
    global _GEMINI_CLIENT

    if _GEMINI_CLIENT is None:
        # HTTP options with explicit timeout for reliability
        # Note: google-genai SDK uses milliseconds for timeout
        http_options = types.HttpOptions(
            timeout=int(DEFAULT_REQUEST_TIMEOUT * 1000),
        )

        logger.debug("Creating Vertex AI client for project=%s, region=%s",
                    VERTEX_PROJECT, VERTEX_REGION)

        if VERTEX_SERVICE_ACCOUNT_JSON:
            # Parse service account JSON from environment
            try:
                sa_info = json.loads(VERTEX_SERVICE_ACCOUNT_JSON)
                credentials = service_account.Credentials.from_service_account_info(  # type: ignore[no-untyped-call]
                    sa_info,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                _GEMINI_CLIENT = genai.Client(
                    vertexai=True,
                    project=VERTEX_PROJECT,
                    location=VERTEX_REGION,
                    credentials=credentials,
                    http_options=http_options,
                )
            except json.JSONDecodeError as e:
                logger.error("Failed to parse VERTEX_AI_SERVICE_ACCOUNT JSON: %s", e)
                raise RuntimeError("Invalid Vertex AI service account configuration")
        else:
            # Fall back to Application Default Credentials (ADC)
            # Works in Cloud Run with attached service account
            logger.debug("Using Application Default Credentials for Vertex AI")
            _GEMINI_CLIENT = genai.Client(
                vertexai=True,
                project=VERTEX_PROJECT,
                location=VERTEX_REGION,
                http_options=http_options,
            )

        logger.info("🏢 Gemini client initialized (connection pooling enabled)")

    return _GEMINI_CLIENT


def _strip_exif_metadata(image_bytes: bytes, mime_type: str) -> bytes:
    """
    Strip EXIF metadata from images for privacy.
    
    EXIF data can contain sensitive info: GPS coordinates, device identifiers,
    timestamps, camera settings, etc. We strip it before sending to Gemini.
    
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
        output = io.BytesIO()
        
        if mime_type == "image/jpeg":
            img_rgb = img.convert("RGB") if img.mode != "RGB" else img
            img_rgb.save(output, format="JPEG", quality=95)
        elif mime_type == "image/png":
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(img.get_flattened_data()))
            clean_img.save(output, format="PNG")
        elif mime_type == "image/webp":
            img.save(output, format="WEBP", quality=95)
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


# Default PII patterns for optional scrubbing
# These are basic examples; production use should consider libraries like Microsoft Presidio
DEFAULT_PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    "phone_us": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "credit_card": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
}


@dataclass
class GeminiConfig:
    """Configuration for Gemini requests."""
    model: str
    max_tokens: int = 4000
    temperature: float = 1.0
    top_p: float = 0.95
    top_k: int = 40


class GeminiProvider:
    """
    Gemini provider using Vertex AI platform.
    
    Usage:
        provider = GeminiProvider()
        
        # Stream response
        for chunk in provider.stream("Hello!", model="gemini-2.5-flash"):
            print(chunk, end="")
    """
    
    def __init__(
        self,
        allowed_regions: Optional[List[str]] = None,
        pii_scrubber: Optional[Callable[[str], str]] = None,
        strip_metadata: bool = True,
    ):
        """
        Initialize Gemini provider with Vertex AI.

        Args:
            allowed_regions: Optional list of allowed GCP regions for data sovereignty.
                           If specified and the configured region is not in the list,
                           raises ValueError.
            pii_scrubber: Optional callback function to scrub PII from messages
                         before sending to the API. Signature: (str) -> str
            strip_metadata: If True, don't log filenames/sensitive metadata (default: True).

        Note:
            Uses a singleton client for connection pooling. This dramatically
            improves TTFT by reusing HTTP connections instead of creating
            fresh TLS handshakes per request.
        """
        self.pii_scrubber = pii_scrubber
        self.strip_metadata = strip_metadata
        self.backend = "vertex_ai"

        # Privacy Control: Enforce region allow-list
        if allowed_regions:
            if VERTEX_REGION not in allowed_regions:
                raise ValueError(
                    f"Privacy Violation: Region '{VERTEX_REGION}' is not in allowed list {allowed_regions}. "
                    f"This may violate data sovereignty requirements."
                )

        # Use singleton client for connection pooling (improves TTFT)
        self.client = _get_gemini_client()
    
    def stream(
        self,
        message: str,
        model: str,
        system_instruction: Optional[str] = None,
        max_tokens: int = 4000,
        file_data: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 1.0,
        web_search_enabled: bool = False,
    ) -> Generator[str, None, Dict[str, Any]]:
        """
        Stream a response from Gemini.
        
        Args:
            message: User message
            model: Model name (e.g., "gemini-2.5-flash")
            system_instruction: Optional system prompt
            max_tokens: Maximum output tokens
            file_data: Optional list of file attachments [{bytes, mime_type, name}]
            temperature: Sampling temperature (0.0-2.0)
            web_search_enabled: Enable Google Search grounding for real-time info
            
        Yields:
            Text chunks as they arrive
            
        Returns:
            Dict with 'citations' list containing web search sources (via generator return)
        """
        # Privacy Control: Warn about experimental/preview models
        # Google's terms may treat preview/experimental data differently than GA models
        is_experimental = "preview" in model or "exp" in model
        if is_experimental:
            logger.warning(
                "⚠️ Using experimental model '%s'. Data terms may differ from GA models. "
                "Ensure this is acceptable for your use case.", model
            )
        
        # Privacy Control: Apply PII scrubbing if configured
        processed_message = message
        if self.pii_scrubber:
            processed_message = self.pii_scrubber(message)
            if processed_message != message:
                logger.debug("PII scrubber modified message before sending")
        
        # Build content parts
        contents = self._build_contents(processed_message, file_data)
        
        # Build generation config with explicit safety settings
        # Being explicit is better than relying on potentially changing defaults
        config = types.GenerateContentConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
            top_p=0.95,
            top_k=40,
            # Explicit safety settings - don't rely on defaults
            safety_settings=[
                types.SafetySetting(
                    category="HARM_CATEGORY_HATE_SPEECH",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_HARASSMENT",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
            ],
        )
        
        # Add Google Search tool for web grounding if enabled
        if web_search_enabled:
            google_search_tool = types.Tool(google_search=types.GoogleSearch())
            config.tools = [google_search_tool]
            logger.debug("Web search enabled for Gemini request")
        
        if system_instruction:
            # Apply PII scrubber to system_instruction as well
            processed_system_instruction = system_instruction
            if self.pii_scrubber:
                processed_system_instruction = self.pii_scrubber(system_instruction)
                if processed_system_instruction != system_instruction:
                    logger.debug("PII scrubber modified system_instruction before sending")
            config.system_instruction = processed_system_instruction
        
        # Stream response
        citations: List[Dict[str, Any]] = []
        usage_info: Dict[str, int] = {}
        try:
            response_stream = self.client.models.generate_content_stream(  # type: ignore[misc]
                model=model,
                contents=contents,
                config=config,
            )

            final_response = None
            for chunk in response_stream:
                final_response = chunk  # Keep track of final chunk for grounding metadata + usage
                if chunk.text:
                    yield chunk.text
            
            # Extract usage metadata from final response
            if final_response:
                usage_metadata = getattr(final_response, 'usage_metadata', None)
                if usage_metadata:
                    usage_info = {
                        'input_tokens': getattr(usage_metadata, 'prompt_token_count', 0) or 0,
                        'output_tokens': getattr(usage_metadata, 'candidates_token_count', 0) or 0,
                    }
            
            # Extract citations from grounding metadata (available in final response)
            if web_search_enabled and final_response:
                try:
                    grounding_metadata = getattr(
                        final_response.candidates[0] if final_response.candidates else None,
                        'grounding_metadata', None
                    )
                    if grounding_metadata:
                        grounding_chunks = getattr(grounding_metadata, 'grounding_chunks', []) or []
                        for idx, gc in enumerate(grounding_chunks):
                            web_info = getattr(gc, 'web', None)
                            if web_info:
                                citations.append({
                                    'index': idx + 1,
                                    'url': getattr(web_info, 'uri', ''),
                                    'title': getattr(web_info, 'title', 'Source'),
                                })
                        if citations:
                            logger.debug("Extracted %d citations from Gemini grounding", len(citations))
                except Exception as e:
                    logger.warning("Failed to extract Gemini citations: %s", type(e).__name__)
            
            # Return citations and usage via generator return value
            return {'citations': citations, 'usage': usage_info}
                    
        except Exception as e:
            # Tightened logging: avoid leaking prompts via exception strings
            # Extract only safe attributes - NEVER use %r which may expose request content
            status_code = getattr(e, "status_code", getattr(e, "code", "n/a"))
            error_reason = getattr(e, "reason", "n/a")
            logger.error("Gemini streaming error (%s, %s, status=%s)", 
                        self.backend, type(e).__name__, status_code)
            logger.debug("Gemini error attrs: reason=%s", error_reason)
            
            error_msg = str(e)
            error_lower = error_msg.lower()
            
            # Provide user-friendly error messages (sanitized - no raw error in user output)
            # Use 'from None' to suppress exception context and prevent traceback leakage
            if "429" in error_msg or "quota" in error_lower:
                raise RateLimitError("Rate limited by Gemini API. Please try again later.") from None
            elif "401" in error_msg or "403" in error_msg or "permission" in error_lower:
                raise AuthenticationError("Authentication failed. Please check your credentials.") from None
            elif status_code == 404 or "model not found" in error_lower or ("models/" in error_lower and "not found" in error_lower):
                # Only trigger ModelNotFoundError for actual model-not-found errors
                # Avoid false positives from errors like "model received invalid input"
                raise ModelNotFoundError(f"Model '{model}' is not available.") from None
            else:
                # Include error details for debugging (sanitized to avoid PII)
                # This helps identify the root cause while keeping user-friendly messages
                safe_error = error_lower[:200] if len(error_lower) > 200 else error_lower
                logger.warning("Gemini API error details: %s", safe_error)
                raise GeminiAPIError("Gemini API error. Please try again.") from None
        finally:
            # Best-effort memory cleanup for sensitive data
            # Python doesn't offer secure memory wiping, but explicit deletion
            # helps garbage collection and reduces exposure window
            try:
                del contents
                if file_data:
                    for fd in file_data:
                        if 'bytes' in fd:
                            fd['bytes'] = None
                gc.collect()
            except Exception:
                pass  # Cleanup is best-effort
    
    def _build_contents(
        self, 
        message: str, 
        file_data: Optional[List[Dict[str, Any]]] = None
    ) -> List[types.Content]:
        """
        Build content parts for the API request.
        
        PRIVACY NOTE: We use types.Part.from_bytes (inline data) exclusively.
        This is intentional - the alternative (File API with file URIs) would
        upload files to Google storage buckets, creating persistence and
        lifecycle management concerns. By using inline data, file content
        exists only within the ephemeral request context.
        
        DO NOT use file_uris or the File API to maintain stateless behavior.
        """
        parts: List[Any] = []
        
        # Mime types that Gemini doesn't support but are text-based
        # These should be converted to text/plain
        TEXT_BASED_MIMES_TO_CONVERT = {
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-javascript",
            "application/typescript",
            "application/x-yaml",
            "application/yaml",
            "application/toml",
            "application/x-sh",
            "application/x-python",
            "text/markdown",
            "text/x-markdown",
            "text/csv",
            "text/xml",
        }
        
        # Add file attachments first (if any)
        if file_data:
            for fd in file_data:
                file_bytes = fd.get("bytes")
                mime_type = fd.get("mime_type", "application/octet-stream")
                filename = fd.get("name", "file")
                
                if file_bytes:
                    # Strip EXIF metadata from images for privacy
                    if mime_type.startswith("image/"):
                        file_bytes = _strip_exif_metadata(file_bytes, mime_type)
                        # Conditional logging based on privacy settings
                        if not self.strip_metadata:
                            logger.debug("Added image to request: %s (%s, %d bytes, EXIF stripped)",
                                       filename, mime_type, len(file_bytes))
                        else:
                            logger.debug("Added image (%s, %d bytes, EXIF stripped)",
                                       mime_type, len(file_bytes))
                    
                    # Convert unsupported text-based mime types to text/plain
                    # Gemini rejects application/json and similar, but handles text/plain fine
                    if mime_type in TEXT_BASED_MIMES_TO_CONVERT:
                        logger.debug("Converting mime type %s to text/plain for Gemini compatibility", mime_type)
                        mime_type = "text/plain"
                    
                    # PRIVACY: Use inline data (from_bytes), NOT file URIs
                    # This ensures file data is ephemeral and not persisted
                    parts.append(types.Part.from_bytes(
                        data=file_bytes,
                        mime_type=mime_type,
                    ))
        
        # Add text message
        parts.append(types.Part.from_text(text=message))
        
        return [types.Content(role="user", parts=parts)]
    
    @staticmethod
    def get_privacy_info() -> Dict[str, Any]:
        """Get privacy metadata for Gemini (Vertex AI).
        
        Returns:
            Privacy metadata dict for Vertex AI backend
        """
        return {
            "provider": "gemini",
            "provider_name": "Google Gemini",
            "docs_url": "https://cloud.google.com/vertex-ai/generative-ai/docs/data-governance",
            # Privacy features
            "privacy_features": {
                "pii_scrubber_support": True,  # Optional callback for PII redaction
                "exif_stripping": True,  # We strip EXIF from images
                "filename_redaction": True,  # strip_metadata defaults to True
                "inline_data_only": True,  # We use inline data, NOT File API (no persistence)
            },
            "backend": "vertex_ai",
            "data_retention": "Request data not used for model training",
            "data_location": f"Processed in {VERTEX_REGION}",
            "training_opt_out": True,
            "enterprise_grade": True,
            "compliance": ["SOC 2", "ISO 27001", "HIPAA eligible"],
            "privacy_summary": "Enterprise Vertex AI - Data not used for training, processed in specified region",
            "privacy_level": "high",
            # Caching disclosure
            "caching_info": {
                "implicit_caching": True,
                "opt_out_available": False,
                "description": "Gemini uses implicit prompt caching for performance. There is no opt-out mechanism.",
                "explicit_caching_used": False,  # We don't use explicit/context caching
                "user_notice": "Your prompts may be cached server-side for performance optimization. This is automatic and cannot be disabled.",
            },
            # Data residency info
            "data_residency": {
                "region": VERTEX_REGION,
                "configurable": True,
                "region_allowlist_enforced": True,  # We enforce allowed_regions parameter
                "note": f"Data processed in {VERTEX_REGION}. Region can be configured at deployment time.",
            },
        }


# -----------------------------
# Custom Exceptions
# -----------------------------

class GeminiAPIError(Exception):
    """Base exception for Gemini API errors."""
    pass


class RateLimitError(GeminiAPIError):
    """Rate limit exceeded."""
    pass


class AuthenticationError(GeminiAPIError):
    """Authentication or authorization failed."""
    pass


class ModelNotFoundError(GeminiAPIError):
    """Requested model not available."""
    pass


# -----------------------------
# Convenience Functions
# -----------------------------

def create_default_pii_scrubber(
    patterns: Optional[Dict[str, str]] = None,
    replacement: str = "[REDACTED]",
) -> Callable[[str], str]:
    """
    Create a basic PII scrubber function using regex patterns.
    
    NOTE: This is a basic implementation. For production use with sensitive data,
    consider using robust libraries like Microsoft Presidio or AWS Comprehend.
    
    Args:
        patterns: Dict of {name: regex_pattern}. Uses DEFAULT_PII_PATTERNS if not provided.
        replacement: Replacement string for matched PII.
        
    Returns:
        A function that takes a string and returns it with PII redacted.
    
    Example:
        scrubber = create_default_pii_scrubber()
        provider = GeminiProvider(api_key="...", pii_scrubber=scrubber)
    """
    active_patterns = patterns or DEFAULT_PII_PATTERNS
    
    def scrub(text: str) -> str:
        result = text
        for name, pattern in active_patterns.items():
            result = re.sub(pattern, f"{replacement}", result)
        return result
    
    return scrub


def stream_gemini(
    message: str,
    model: str,
    system_instruction: Optional[str] = None,
    max_tokens: int = 4000,
    file_data: Optional[List[Dict[str, Any]]] = None,
    allowed_regions: Optional[List[str]] = None,
    pii_scrubber: Optional[Callable[[str], str]] = None,
    web_search_enabled: bool = False,
) -> Generator[str, None, Dict[str, Any]]:
    """
    Stream a Gemini response via Vertex AI.
    
    Convenience function that creates a provider and streams.
    
    Args:
        message: User message
        model: Model name
        system_instruction: Optional system prompt
        max_tokens: Maximum output tokens
        file_data: Optional file attachments
        allowed_regions: Optional list of allowed GCP regions
        pii_scrubber: Optional callback to scrub PII before sending
        web_search_enabled: Enable Google Search grounding tool
        
    Yields:
        Text chunks
        
    Returns:
        Dict with 'citations' list when web search is enabled
    """
    provider = GeminiProvider(
        allowed_regions=allowed_regions,
        pii_scrubber=pii_scrubber,
    )
    return (yield from provider.stream(
        message=message,
        model=model,
        system_instruction=system_instruction,
        max_tokens=max_tokens,
        file_data=file_data,
        web_search_enabled=web_search_enabled,
    ))


def get_gemini_privacy_info() -> Dict[str, Any]:
    """
    Get privacy info for Gemini (Vertex AI).
    
    Returns:
        Privacy metadata dict
    """
    return GeminiProvider.get_privacy_info()
