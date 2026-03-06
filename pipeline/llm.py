"""LLM transport layer: Claude CLI wrapper + cost tracking + caching."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


class LLMError(Exception):
    """Raised when LLM call fails."""


class LLMParseError(LLMError):
    """Raised when JSON extraction fails. Includes raw response."""

    def __init__(self, message: str, raw_response: str):
        super().__init__(message)
        self.raw_response = raw_response


class CostTracker:
    """Tracks LLM call count and estimated cost."""

    def __init__(self, max_calls: int = 50):
        self.max_calls = max_calls
        self.call_count = 0
        self.total_prompt_chars = 0
        self.total_response_chars = 0

    def record(self, prompt_len: int, response_len: int) -> None:
        self.call_count += 1
        self.total_prompt_chars += prompt_len
        self.total_response_chars += response_len

    def check_budget(self) -> None:
        if self.call_count >= self.max_calls:
            raise LLMError(
                f"LLM budget exhausted: {self.call_count}/{self.max_calls} calls used. "
                f"Increase max_llm_calls in config to continue."
            )

    @property
    def estimated_cost_usd(self) -> float:
        # Rough estimate: ~$0.01 per 1k chars input, ~$0.03 per 1k chars output
        return (
            self.total_prompt_chars * 0.01 + self.total_response_chars * 0.03
        ) / 1000


class LLMClient:
    """Claude CLI wrapper with cost tracking and optional response caching."""

    def __init__(
        self,
        default_timeout: int = 180,
        max_calls: int = 50,
        cache_dir: Path | None = None,
    ):
        self.default_timeout = default_timeout
        self.cost = CostTracker(max_calls)
        self.cache_dir = cache_dir  # None = no caching

    def ask(
        self,
        prompt: str,
        system_prompt: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """One-shot claude -p call. Returns text response."""
        self.cost.check_budget()

        # Check cache
        cache_key = self._cache_key(prompt, system_prompt)
        if self.cache_dir and (cached := self._cache_get(cache_key)):
            return cached

        cmd = ["claude", "-p"]
        if system_prompt:
            cmd.extend(["--system-prompt", system_prompt])

        # Strip CLAUDECODE env var to avoid nested-session detection
        env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

        try:
            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise LLMError(
                f"claude -p timed out after {timeout or self.default_timeout}s"
            ) from e

        if result.returncode != 0:
            raise LLMError(f"claude -p failed: {result.stderr[:500]}")

        response = result.stdout
        self.cost.record(len(prompt), len(response))

        # Write cache
        if self.cache_dir:
            self._cache_put(cache_key, response)

        return response

    def ask_structured(
        self,
        prompt: str,
        system_prompt: str | None = None,
        timeout: int | None = None,
    ) -> dict:
        """Ask and extract JSON from response."""
        response = self.ask(prompt, system_prompt, timeout)
        return _extract_json(response)

    def _cache_key(self, prompt: str, system_prompt: str | None) -> str:
        content = f"{system_prompt or ''}|{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _cache_get(self, key: str) -> str | None:
        path = self.cache_dir / f"{key}.txt"
        return path.read_text() if path.exists() else None

    def _cache_put(self, key: str, response: str) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / f"{key}.txt").write_text(response)


def _extract_json(text: str) -> dict:
    """Extract JSON from LLM response. Handles common LLM output patterns.

    Strategy (in order):
    1. Try json.loads(text) directly
    2. Extract from ```json ... ``` fences
    3. Extract from ``` ... ``` fences
    4. Find first '{' to last '}' and parse
    5. Raise LLMParseError with raw response
    """
    # 1. Direct parse
    text_stripped = text.strip()
    try:
        return json.loads(text_stripped)
    except json.JSONDecodeError:
        pass

    # 2. JSON code fence
    match = re.search(r"```json\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Generic code fence
    match = re.search(r"```\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 4. First '{' to last '}'
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace : last_brace + 1])
        except json.JSONDecodeError:
            pass

    # 5. Give up
    raise LLMParseError(
        f"Could not extract JSON from LLM response ({len(text)} chars)",
        raw_response=text,
    )


def _extract_solidity(text: str) -> str:
    """Extract Solidity code from LLM response."""
    match = re.search(r"```solidity\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"```\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    # If no fences, assume entire response is code
    return text.strip()
