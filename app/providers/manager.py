import json
import os
from pathlib import Path
from typing import Any
from .base import ModelConfig, ModelProvider
from .ollama import OllamaProvider
from .openai_compatible import OpenAICompatibleProvider
from .anthropic import AnthropicProvider

class ModelManager:
    """Loads non-secret provider/model routing from JSON; secrets only come from environment."""
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.data: dict[str, Any] = {}
        self.reload()

    def reload(self):
        if not self.config_path.exists():
            raise FileNotFoundError(f"Model config not found: {self.config_path}")
        self.data = json.loads(self.config_path.read_text(encoding="utf-8"))

    def public_config(self) -> dict:
        providers = {}
        for name, item in self.data.get("providers", {}).items():
            env_name = item.get("api_key_env", "")
            providers[name] = {"type": item.get("type"), "base_url": item.get("base_url"),
                               "api_key_env": env_name, "api_key_configured": bool(env_name and os.getenv(env_name)),
                               "default_model": item.get("default_model")}
        return {"active_provider": self.data.get("active_provider"), "providers": providers,
                "agent_models": self.data.get("agent_models", {}),
                "generation_enabled": False}

    def resolve(self, agent_name: str | None = None) -> tuple[ModelConfig, ModelProvider]:
        provider_name = self.data.get("agent_providers", {}).get(agent_name, self.data.get("active_provider", "ollama")) if agent_name else self.data.get("active_provider", "ollama")
        provider_data = self.data.get("providers", {}).get(provider_name)
        if not provider_data:
            raise ValueError(f"Unknown model provider configured for {agent_name or 'default'}: {provider_name}")
        model = self.data.get("agent_models", {}).get(agent_name, provider_data.get("default_model", ""))
        cfg = ModelConfig(provider=provider_name, model=model, base_url=provider_data.get("base_url", ""),
                          api_key_env=provider_data.get("api_key_env", ""),
                          timeout_seconds=int(provider_data.get("timeout_seconds", 120)),
                          max_tokens=int(provider_data.get("max_tokens", 2048)))
        kind = provider_data.get("type")
        if kind == "ollama":
            instance = OllamaProvider(cfg.base_url)
        elif kind == "openai_compatible":
            instance = OpenAICompatibleProvider(cfg.base_url, cfg.api_key_env or "OPENAI_API_KEY")
        elif kind == "anthropic":
            instance = AnthropicProvider(cfg.base_url or "https://api.anthropic.com", cfg.api_key_env or "ANTHROPIC_API_KEY")
        else:
            raise ValueError(f"Unsupported provider type: {kind}")
        return cfg, instance

    def list_provider_models(self) -> dict:
        results = {}
        for name, item in self.data.get("providers", {}).items():
            try:
                kind = item.get("type")
                if kind == "ollama":
                    provider = OllamaProvider(item.get("base_url", "http://127.0.0.1:11434"))
                elif kind == "openai_compatible":
                    provider = OpenAICompatibleProvider(item.get("base_url", "https://api.openai.com/v1"), item.get("api_key_env", "OPENAI_API_KEY"))
                elif kind == "anthropic":
                    provider = AnthropicProvider(item.get("base_url", "https://api.anthropic.com"), item.get("api_key_env", "ANTHROPIC_API_KEY"))
                else:
                    results[name] = {"connected": False, "models": [], "error": "Unsupported provider"}; continue
                results[name] = provider.list_models()
            except Exception as exc:
                results[name] = {"connected": False, "models": [], "error": str(exc)}
        return results
