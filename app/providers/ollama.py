import requests
from .base import ModelProvider

class OllamaProvider(ModelProvider):
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def generate(self, *, model: str, system: str, prompt: str, timeout: int = 120, max_tokens: int = 2048) -> str:
        response = requests.post(
            f"{self.base_url}/api/chat",
            json={"model": model, "stream": False, "messages": [
                {"role": "system", "content": system}, {"role": "user", "content": prompt}
            ], "options": {"num_predict": max_tokens}}, timeout=timeout)
        response.raise_for_status()
        content = response.json().get("message", {}).get("content", "").strip()
        if not content:
            raise RuntimeError("Ollama returned an empty response")
        return content

    def list_models(self) -> dict:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            return {"connected": True, "models": [m.get("name", "") for m in response.json().get("models", [])]}
        except (requests.RequestException, ValueError) as exc:
            return {"connected": False, "models": [], "error": str(exc)}
