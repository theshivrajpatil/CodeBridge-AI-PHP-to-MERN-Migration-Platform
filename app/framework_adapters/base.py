"""Framework adapter contracts. Adapters provide hints; the PHP core stays framework-neutral."""
from dataclasses import dataclass
from typing import Protocol

@dataclass
class Detection:
    name: str
    confidence: str
    evidence: list[str]
    adapter_id: str

class FrameworkAdapter(Protocol):
    adapter_id: str
    display_name: str
    def detect(self, paths: set[str]) -> Detection | None: ...
    def classify(self, path: str) -> dict | None: ...
