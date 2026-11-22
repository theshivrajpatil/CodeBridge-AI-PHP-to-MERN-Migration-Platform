"""Stage runner for the V5.18–V5.22 intelligence engines (framework-independent, cached per root)."""
from __future__ import annotations

from pathlib import Path

from app.auth_intelligence import build_auth_intelligence
from app.contract_extraction import extract_behavioural_contracts
from app.dependency_graph import build_dependency_graph
from app.routes_intelligence import build_routes_intelligence
from app.validation_response import build_validation_response_analysis

STAGES = {"dependency-graph": "dependency_graph", "contracts": "contracts", "routes": "routes",
          "auth": "auth", "validation-response": "validation_response"}
_CACHE: dict[str, dict] = {}


def run_stage(root: str | Path, stage: str) -> dict:
    """Run one stage (and its prerequisites) for ``root``; results are cached by resolved root."""
    if stage not in STAGES:
        raise ValueError(f"Unknown stage: {stage}")
    key = str(Path(root).resolve(strict=True))
    state = _CACHE.setdefault(key, {})
    state["dependency_graph"] = state.get("dependency_graph") or build_dependency_graph(key)
    graph = state["dependency_graph"]
    if stage != "dependency-graph":
        state["contracts"] = state.get("contracts") or extract_behavioural_contracts(key, graph)
        ids = {c["id"] for c in state["contracts"]["callable_contracts"]}
    if stage in {"routes", "auth", "validation-response"}:
        state["routes"] = state.get("routes") or build_routes_intelligence(key, graph, ids)
    if stage == "auth":
        state["auth"] = state.get("auth") or build_auth_intelligence(key, graph, state["contracts"], state["routes"])
    if stage == "validation-response":
        state["validation_response"] = state.get("validation_response") or build_validation_response_analysis(
            key, graph, state["contracts"], state["routes"])
    return state[STAGES[stage]]


def clear_cache(root: str | Path | None = None) -> None:
    if root is None:
        _CACHE.clear()
    else:
        _CACHE.pop(str(Path(root).resolve()), None)
