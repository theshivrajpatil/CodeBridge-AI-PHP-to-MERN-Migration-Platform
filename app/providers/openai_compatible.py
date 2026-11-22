import os
import requests
from .base import ModelProvider

class OpenAICompatibleProvider(ModelProvider):
    """OpenAI Chat Completions-compatible endpoint (OpenAI or compatible gateway)."""
    def __init__(self, base_url: str, api_key_env: str = "OPENAI_API_KEY"):
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env

    def _key(self):
        key = os.getenv(self.api_key_env, "").strip()
        if not key:
            raise RuntimeError(f"Missing API key. Set environment variable {self.api_key_env}.")
        return key

    def generate(self, *, model: str, system: str, prompt: str, timeout: int = 120, max_tokens: int = 2048) -> str:
        response = requests.post(f"{self.base_url}/chat/completions", headers={
            "Authorization": f"Bearer {self._key()}", "Content-Type": "application/json"
        }, json={"model": model, "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": prompt}
        ], "max_tokens": max_tokens}, timeout=timeout)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"].get("content", "")
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        content = str(content).strip()
        if not content:
            raise RuntimeError("OpenAI-compatible provider returned an empty response")
        return content

    def list_models(self) -> dict:
        try:
            response = requests.get(f"{self.base_url}/models", headers={"Authorization": f"Bearer {self._key()}"}, timeout=10)
            response.raise_for_status()
            return {"connected": True, "models": [x.get("id", "") for x in response.json().get("data", [])]}
        except Exception as exc:
            return {"connected": False, "models": [], "error": str(exc)}
