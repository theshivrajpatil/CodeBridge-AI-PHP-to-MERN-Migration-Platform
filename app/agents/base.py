from abc import ABC, abstractmethod
from typing import Any

class Agent(ABC):
    name = "base_agent"
    description = "Base CodeBridge agent"
    mode = "deterministic"

    @abstractmethod
    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError
