"""
Echo provider for e2e testing.

Echoes back the user's message word-by-word to simulate streaming.
No external API calls. Only active when ENABLE_TEST_PROVIDER=true.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


def stream_echo(
    message: str,
    model: str = "echo-1",
    system_instruction: Optional[str] = None,
    max_tokens: int = 4000,
    file_data: Optional[List[Dict[str, Any]]] = None,
    temperature: float = 1.0,
    web_search_enabled: bool = False,
) -> Generator[str, None, Dict[str, Any]]:
    """Stream an echo response, yielding the message back word-by-word.

    Matches the stream_openai/stream_anthropic interface:
    yields str chunks, returns dict via StopIteration.value.
    """
    prefix = "[echo] "
    yield prefix

    if file_data:
        file_note = f"(received {len(file_data)} file(s)) "
        yield file_note

    words = message.split()
    for i, word in enumerate(words):
        chunk = word if i == len(words) - 1 else word + " "
        yield chunk
        time.sleep(0.01)  # Simulate streaming delay

    total_chars = len(prefix) + len(message)
    return {
        "usage": {
            "input_tokens": len(words),
            "output_tokens": total_chars // 4,
        },
        "citations": [],
    }


def get_echo_privacy_info() -> Dict[str, Any]:
    """Get privacy info for the echo test provider."""
    return {
        "provider": "echo",
        "provider_name": "Echo (Test)",
        "privacy_summary": "Test provider - no external API calls, data stays in-process",
        "privacy_level": "high",
        "training_opt_out": True,
        "data_retention": "None - in-memory only",
        "backend": "local",
    }
