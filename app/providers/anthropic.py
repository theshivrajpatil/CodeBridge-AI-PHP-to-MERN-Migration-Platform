import os
import requests
from .base import ModelProvider

class AnthropicProvider(ModelProvider):
    def __init__(self, base_url: str = "https://api.anthropic.com", api_key_env: str = "ANTHROPIC_API_KEY", api_version: str = "2023-06-01"):
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self.api_version = api_version

    def _key(self):
        key = os.getenv(self.api_key_env, "").strip()
        if not key:
            raise RuntimeError(f"Missing API key. Set environment variable {self.api_key_env}.")
        return key

    def generate(self, *, model: str, system: str, prompt: str, timeout: int = 120, max_tokens: int = 2048) -> str:
        response = requests.post(f"{self.base_url}/v1/messages", headers={
            "x-api-key": self._key(), "anthropic-version": self.api_version, "content-type": "application/json"
        }, json={"model": model, "system": system, "max_tokens": max_tokens,
                 "messages": [{"role": "user", "content": prompt}]}, timeout=timeout)
        response.raise_for_status()
        blocks = response.json().get("content", [])
        content = "".join(block.get("text", "") for block in blocks if block.get("type") == "text").strip()
        if not content:
            raise RuntimeError("Anthropic returned an empty response")
        return content

    def list_models(self) -> dict:
        # Anthropic model discovery is not assumed; use configured model IDs.
        return {"connected": bool(os.getenv(self.api_key_env)), "models": [], "note": "Anthropic model IDs are configured explicitly."}
