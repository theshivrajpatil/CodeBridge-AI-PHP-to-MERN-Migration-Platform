from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass
class ModelConfig:
    provider: str
    model: str
    base_url: str = ""
    api_key_env: str = ""
    timeout_seconds: int = 120
    max_tokens: int = 2048

class ModelProvider(ABC):
    @abstractmethod
    def generate(self, *, model: str, system: str, prompt: str, timeout: int = 120, max_tokens: int = 2048) -> str:
        raise NotImplementedError

    @abstractmethod
    def list_models(self) -> dict[str, Any]:
        raise NotImplementedError
