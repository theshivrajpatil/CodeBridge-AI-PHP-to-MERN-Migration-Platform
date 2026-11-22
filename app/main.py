import json, re, os, tempfile
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.migration_units import approval_store_path, approval_store_lock, load_approval_store, save_approval_store, apply_decision, validate_unit_sources
from app.config import PROJECT_ROOT, WORKSPACE, DEFAULT_MODEL, DEFAULT_OLLAMA_URL, MAX_FILE_BYTES
from app.scanner import scan_repository
from app.planner import build_plan
from app.migration_spec import build_migration_spec
from app.analyzer import analyze_repository
from app.mern_generator import generation_enabled, generation_status, generate_mern_project, preview_generation, resolve_output_root, GenerationError
from app.parity_engine import run_parity, build_source_contracts, resolve_target_root
from app.differential_testing import RuntimeConfig, generate_cases, run_differential
from app.intelligence_pipeline import STAGES as INTEL_STAGES, run_stage, clear_cache as clear_intel_cache
from app.ollama_client import list_models
from app.agents import AgentOrchestrator
from app.providers import ModelManager
from app.config import PROJECT_ROOT
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

MODEL_MANAGER = ModelManager(PROJECT_ROOT / "config" / "models.json")
AGENT_ORCHESTRATOR = AgentOrchestrator()

app = FastAPI(title="CodeBridge AI", version="0.16.0")
class NoCacheStaticFiles(StaticFiles):
    """Serve the UI with revalidation so an updated app.js/styles.css is never paired with stale cached files."""
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


app.mount("/static", NoCacheStaticFiles(directory=str(PROJECT_ROOT / "frontend")), name="static")
LATEST_SCAN = None
LATEST_ANALYSIS = None
LATEST_PLAN = None
LATEST_SPECIFICATION = None
SESSION_FILE = WORKSPACE / "latest_session.json"


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Persist JSON atomically so interrupted writes cannot leave truncated reports."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def name_for_root(root: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", Path(root).name)[:60] or "repository"


def _persist_session() -> None:
    """Save report references so the workbench can recover after server restart."""
    if not LATEST_SCAN:
        return
    root_name = name_for_root(LATEST_SCAN["root"])
    _atomic_write_json(SESSION_FILE, {
        "session_version": 1,
        "project_root": LATEST_SCAN["root"],
        "inventory_file": f"{root_name}_inventory.json",
        "analysis_file": f"{root_name}_analysis.json" if LATEST_ANALYSIS is not None else None,
        "plan_file": f"{root_name}_migration_plan.json" if LATEST_PLAN is not None else None,
        "specification_file": f"{root_name}_migration_specification.json" if LATEST_SPECIFICATION is not None else None,
    })


def _restore_session() -> None:
    """Restore only reports belonging to a still-existing source repository."""
    global LATEST_SCAN, LATEST_ANALYSIS, LATEST_PLAN, LATEST_SPECIFICATION
    manifest = _read_json(SESSION_FILE)
    if not isinstance(manifest, dict):
        return
    root = manifest.get("project_root")
    if not isinstance(root, str) or not Path(root).is_dir():
        return
    scan = _read_json(WORKSPACE / str(manifest.get("inventory_file", "")))
    if not isinstance(scan, dict) or scan.get("root") != str(Path(root).resolve()):
        return
    LATEST_SCAN = scan
    analysis_name = manifest.get("analysis_file")
    plan_name = manifest.get("plan_file")
    spec_name = manifest.get("specification_file")
    LATEST_ANALYSIS = _read_json(WORKSPACE / analysis_name) if analysis_name else None
    LATEST_PLAN = _read_json(WORKSPACE / plan_name) if plan_name else None
    LATEST_SPECIFICATION = _read_json(WORKSPACE / spec_name) if spec_name else None


_restore_session()

class ScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=2000)
class UnitDecisionRequest(BaseModel):
    decision: str = Field(min_length=1, max_length=40)
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=2000)
    expected_fingerprint: str = Field(min_length=64, max_length=64)
    confirm_reviewed: bool = False

class RuntimeRequest(BaseModel):
    enabled: bool = False
    source_base_url: str = Field(default="", max_length=300)
    target_base_url: str = Field(default="", max_length=300)
    allow_mutating: bool = False
    ignore_paths: list[str] = Field(default_factory=list, max_length=50)
    path_params: dict[str, str] = Field(default_factory=dict)
    source_token: str | None = Field(default=None, max_length=4096, repr=False)
    target_token: str | None = Field(default=None, max_length=4096, repr=False)

class GenerationApproval(BaseModel):
    reviewer: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=2000)
    source_fingerprint: str = Field(min_length=64, max_length=64)
    approve_all: bool = False
    approved_contract_ids: list[str] = Field(default_factory=list, max_length=2000)
    acknowledged_risks: list[str] = Field(default_factory=list, max_length=2000)

class GenerateRequest(BaseModel):
    project_name: str = Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    approval: GenerationApproval

class ParityRequest(BaseModel):
    target_path: str = Field(min_length=1, max_length=4096)
    exclude_web_routes: bool = True
    runtime: RuntimeRequest | None = None


class ImpactRequest(BaseModel):
    path: str = Field(min_length=1, max_length=2000)

@app.get("/", response_class=HTMLResponse)
def index():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(page, headers={"Cache-Control": "no-cache, must-revalidate"})
@app.get("/api/health")
def health():
    return {"status":"ok","service":"CodeBridge AI","model_default":DEFAULT_MODEL}
@app.get("/api/models")
def models(ollama_url: str = DEFAULT_OLLAMA_URL):
    return list_models(ollama_url)
@app.post("/api/scan")
def scan(request: ScanRequest):
    global LATEST_SCAN, LATEST_ANALYSIS, LATEST_PLAN, LATEST_SPECIFICATION
    try: result = scan_repository(request.path)
    except (ValueError, FileNotFoundError, OSError) as exc: raise HTTPException(status_code=400, detail=str(exc))
    LATEST_SCAN = result
    clear_intel_cache(result["root"])
    LATEST_ANALYSIS = None
    LATEST_PLAN = None
    LATEST_SPECIFICATION = None
    name = name_for_root(result["root"])
    out = WORKSPACE / f"{name}_inventory.json"
    result["report_file"] = str(out)
    _atomic_write_json(out, result)
    _persist_session()
    return {**result, "files": result["files"][:1000]}

@app.post("/api/analyze")
def analyze():
    global LATEST_ANALYSIS
    if not LATEST_SCAN: raise HTTPException(status_code=409, detail="Scan a repository before analysis.")
    LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
    out = WORKSPACE / f"{name}_analysis.json"
    LATEST_ANALYSIS["report_file"] = str(out)
    _atomic_write_json(out, LATEST_ANALYSIS)
    _persist_session()
    return LATEST_ANALYSIS

@app.post("/api/behavior")
def behavior():
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before extracting behaviour contracts.")
    global LATEST_ANALYSIS
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    return LATEST_ANALYSIS.get("behavior_report", {})

@app.post("/api/dependencies")
def dependencies():
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before building dependency intelligence.")
    global LATEST_ANALYSIS
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    result = LATEST_ANALYSIS.get("dependency_intelligence", {})
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
    out = WORKSPACE / f"{name}_dependency_intelligence.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return {**result, "report_file": str(out)}

@app.post("/api/intelligence/{stage}")
def intelligence(stage: str):
    """V5.18-V5.22 engines: dependency-graph | contracts | routes | auth | validation-response."""
    if stage not in INTEL_STAGES:
        raise HTTPException(status_code=404, detail=f"Unknown stage. Use one of: {', '.join(INTEL_STAGES)}")
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before running intelligence engines.")
    try:
        result = run_stage(LATEST_SCAN["root"], stage)
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
    out = WORKSPACE / f"{name}_{stage.replace('-', '_')}.json"
    _atomic_write_json(out, result)
    return {**result, "report_file": str(out)}

@app.post("/api/parity")
def parity(request: ParityRequest):
    """V5.23 Behavioural Parity Engine. Read-only evidence for human review: never approves or authorizes anything."""
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan the PHP source repository before running parity analysis.")
    try:
        target = resolve_target_root(request.target_path, LATEST_SCAN["root"])
        runtime_result = None
        if request.runtime and request.runtime.enabled:
            rt = request.runtime
            cfg = RuntimeConfig(source_base_url=rt.source_base_url, target_base_url=rt.target_base_url, enabled=True,
                                allow_mutating=rt.allow_mutating, ignore_paths=tuple(rt.ignore_paths), path_params=rt.path_params,
                                source_token=rt.source_token, target_token=rt.target_token)
            cases = generate_cases(build_source_contracts(LATEST_SCAN["root"], request.exclude_web_routes)["contracts"], cfg)
            runtime_result = run_differential(cases, cfg)
        report = run_parity(LATEST_SCAN["root"], target, runtime_result, request.exclude_web_routes)
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
    out = WORKSPACE / f"{name}_parity_report.json"
    _atomic_write_json(out, report)
    return {**report, "report_file": str(out)}

_MODELS_CONFIG = Path(__file__).resolve().parent.parent / "config" / "models.json"

_LOCAL_GATE_CONFIG = _MODELS_CONFIG.with_name("models.local.json")   # git-ignored local opt-in; shipped models.json stays disabled

def _gate_config() -> Path:
    return _LOCAL_GATE_CONFIG if _LOCAL_GATE_CONFIG.is_file() else _MODELS_CONFIG

def _generation_enabled() -> bool:
    return generation_enabled(_gate_config(), os.environ)

import logging as _logging
_gen = generation_status(_gate_config(), os.environ)
_logging.getLogger("uvicorn.error").info(
    "Controlled generation: %s", "ENABLED (human approval still required)" if _gen["enabled"]
    else "DISABLED - run `python scripts/enable_generation.py` and restart (" + _gen["instructions"] + ")")

@app.get("/api/generate/status")
def generate_status():
    """Whether controlled generation is enabled and, if not, exactly what must be changed deliberately."""
    return generation_status(_gate_config(), os.environ)

@app.post("/api/generate/preview")
def generate_preview():
    """Read-only: returns the analysis fingerprint and HIGH-risk findings a reviewer must approve/acknowledge."""
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan the PHP source repository first.")
    try:
        return preview_generation(LATEST_SCAN["root"])
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/generate")
def generate(request: GenerateRequest):
    """Final phase: controlled MERN generation. Requires CODEBRIDGE_GENERATION_ENABLED=1 AND a human approval bound to the
    current analysis fingerprint. Writes files only inside workspace/generated; never builds, executes or deploys anything."""
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan the PHP source repository first.")
    enabled = _generation_enabled()
    try:
        out = resolve_output_root(request.project_name, LATEST_SCAN["root"], WORKSPACE / "generated")
        manifest = generate_mern_project(LATEST_SCAN["root"], out, request.approval.model_dump(), enabled, request.project_name)
    except GenerationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if manifest["status"] == "REFUSED":
        raise HTTPException(status_code=403, detail={"message": "Generation refused by the approval gate.", "reasons": manifest["gate"]["reasons"]})
    parity = manifest.pop("parity_report", None)
    return {**manifest, "output_directory": str(out), "generation_authorized": True, "deployment_authorized": False,
            "message": "Files generated for human review. Nothing was built, executed or deployed."}

@app.post("/api/impact")
def dependency_impact(request: ImpactRequest):
    """Return reverse dependency reachability for a repository-relative file path."""
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before requesting impact analysis.")
    global LATEST_ANALYSIS
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    root = Path(LATEST_SCAN["root"]).resolve()
    candidate = Path(request.path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise HTTPException(status_code=400, detail="Use a repository-relative file path.")
    relative = candidate.as_posix().lstrip("./")
    dependency = LATEST_ANALYSIS.get("dependency_intelligence", {})
    known = {node.get("id") for node in dependency.get("nodes", [])}
    if relative not in known:
        raise HTTPException(status_code=404, detail="File is not present in the current dependency graph.")
    impact = (dependency.get("impact_index") or {}).get(relative, [])
    paths = (dependency.get("impact_paths") or {}).get(relative, {})
    direct = sorted(edge.get("from") for edge in dependency.get("edges", [])
                    if edge.get("to") == relative and edge.get("from") in known)
    outgoing = sorted(edge.get("to") for edge in dependency.get("edges", [])
                      if edge.get("from") == relative and edge.get("to") in known)
    return {"selected_file": relative, "dependent_files": impact, "dependent_count": len(impact),
            "direct_dependents": direct, "direct_dependencies": outgoing,
            "impact_paths": paths,
            "subsystems": [x for x in dependency.get("subsystems", []) if relative in x.get("files", [])],
            "status": "STATIC_REVERSE_REACHABILITY_REQUIRES_REVIEW",
            "note": "Dependents are files with a directed static path to this file. Paths show the shortest observed chain; dynamic/runtime dependencies may be missing."}

@app.post("/api/schema")
def schema_intelligence():
    """Return migration-history schema evidence without connecting to a database."""
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before extracting schema intelligence.")
    global LATEST_ANALYSIS
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    intelligence = LATEST_ANALYSIS.get("dependency_intelligence", {})
    return {
        "status": "STATIC_SCHEMA_EVIDENCE_REQUIRES_REVIEW",
        "catalog": intelligence.get("database_schema_catalog", []),
        "operations": intelligence.get("database_schema_operations", []),
        "coverage": intelligence.get("coverage", {}),
        "database_policy": "No database connection or mutation is performed. Migration history is not proof of the deployed schema."
    }

@app.get("/api/coverage")
def analysis_coverage():
    """Expose analysis coverage and unresolved areas without overstating certainty."""
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before requesting analysis coverage.")
    global LATEST_ANALYSIS
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    analysis = LATEST_ANALYSIS
    dependency = analysis.get("dependency_intelligence", {})
    behaviour = analysis.get("behavior_report", {})
    return {
        "inventory": {"files": LATEST_SCAN.get("file_count", 0), "php_files": LATEST_SCAN.get("php_file_count", 0)},
        "php_analysis": {"discovered": analysis.get("php_files_discovered", 0),
                         "analysed": analysis.get("php_files_analyzed", 0),
                         "ast_parsed": analysis.get("ast_files_parsed", 0)},
        "dependencies": {"edge_count": dependency.get("edge_count", 0),
                         "coverage": dependency.get("coverage", {}),
                         "unresolved_relationships": dependency.get("unresolved_relationships", []),
                         "dynamic_uncertainties": dependency.get("dynamic_uncertainties", [])},
        "behaviour": behaviour,
        "limitations": analysis.get("limitations", []),
        "generation_enabled": False
    }

@app.post("/api/plan")
def plan():
    global LATEST_ANALYSIS, LATEST_PLAN
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before building a plan.")
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    LATEST_PLAN = build_plan(LATEST_SCAN, LATEST_ANALYSIS)
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
    out = WORKSPACE / f"{name}_migration_plan.json"
    LATEST_PLAN["report_file"] = str(out)
    _atomic_write_json(out, LATEST_PLAN)
    _persist_session()
    return LATEST_PLAN

@app.post("/api/specification")
def specification():
    global LATEST_ANALYSIS, LATEST_PLAN, LATEST_SPECIFICATION
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before generating a migration specification.")
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    if LATEST_PLAN is None:
        LATEST_PLAN = build_plan(LATEST_SCAN, LATEST_ANALYSIS)
    # A failed regeneration must not leave an older specification looking current.
    LATEST_SPECIFICATION = None
    _persist_session()
    try:
        if LATEST_ANALYSIS is not None:
            analysis_out = WORKSPACE / f"{name_for_root(LATEST_SCAN['root'])}_analysis.json"
            LATEST_ANALYSIS["report_file"] = str(analysis_out)
            _atomic_write_json(analysis_out, LATEST_ANALYSIS)
        if LATEST_PLAN is not None:
            plan_out = WORKSPACE / f"{name_for_root(LATEST_SCAN['root'])}_migration_plan.json"
            LATEST_PLAN["report_file"] = str(plan_out)
            _atomic_write_json(plan_out, LATEST_PLAN)
        specification_data = build_migration_spec(LATEST_SCAN, LATEST_ANALYSIS, LATEST_PLAN)
        if not isinstance(specification_data, dict):
            raise ValueError("Specification builder returned an invalid document.")
        units = specification_data.get("migration_units")
        if not isinstance(units, list):
            raise ValueError("Specification is missing the migration_units list.")
        if specification_data.get("project_root") != LATEST_SCAN.get("root"):
            raise ValueError("Specification project root does not match the scanned repository.")
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
        out = WORKSPACE / f"{name}_migration_specification.json"
        specification_data["report_file"] = str(out)
        specification_data["generation_metadata"] = {
            "validated": True,
            "migration_unit_count": len(units),
            "generation_enabled": False,
            "database_mutations_enabled": False,
        }
        _atomic_write_json(out, specification_data)
        # Read-after-write verification catches filesystem/serialization problems.
        persisted = _read_json(out)
        if not isinstance(persisted, dict) or persisted.get("project_root") != LATEST_SCAN.get("root") or not isinstance(persisted.get("migration_units"), list):
            raise ValueError("Saved specification failed read-after-write validation.")
        LATEST_SPECIFICATION = persisted
        _persist_session()
        return LATEST_SPECIFICATION
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Migration specification generation failed: {type(exc).__name__}: {exc}") from exc

@app.get("/api/state")
def workbench_state():
    """Small restart-safe state summary used to restore the workbench UI."""
    if not LATEST_SCAN:
        return {"restored": False, "scanned": False, "specification_ready": False}
    return {
        "restored": True,
        "scanned": True,
        "project_root": LATEST_SCAN.get("root"),
        "file_count": LATEST_SCAN.get("file_count", 0),
        "php_file_count": LATEST_SCAN.get("php_file_count", 0),
        "framework_hints": LATEST_SCAN.get("framework_hints", []),
        "files": LATEST_SCAN.get("files", [])[:1000],
        "php_files": LATEST_SCAN.get("php_files", []),
        "report_file": LATEST_SCAN.get("report_file"),
        "plan_ready": LATEST_PLAN is not None,
        "specification_ready": LATEST_SPECIFICATION is not None,
        "specification": ({
            "status": LATEST_SPECIFICATION.get("status"),
            "report_file": LATEST_SPECIFICATION.get("report_file"),
            "unit_count": len(LATEST_SPECIFICATION.get("migration_units", [])),
            "framework": LATEST_SPECIFICATION.get("framework_detection", {}).get("name", "Unknown"),
        } if LATEST_SPECIFICATION else None),
    }


@app.get("/api/migration-units")
def migration_units():
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository and generate a migration specification first.")
    global LATEST_ANALYSIS, LATEST_PLAN, LATEST_SPECIFICATION
    if LATEST_ANALYSIS is None:
        LATEST_ANALYSIS = analyze_repository(LATEST_SCAN)
    if LATEST_PLAN is None:
        LATEST_PLAN = build_plan(LATEST_SCAN, LATEST_ANALYSIS)
    if LATEST_SPECIFICATION is None:
        LATEST_SPECIFICATION = build_migration_spec(LATEST_SCAN, LATEST_ANALYSIS, LATEST_PLAN)

    units = LATEST_SPECIFICATION.get("migration_units", [])
    store_path = approval_store_path(WORKSPACE, LATEST_SCAN["root"])
    try:
        with approval_store_lock(store_path):
            store = load_approval_store(store_path)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    decisions = store.get("decisions", {})
    for unit in units:
        sources_valid, changed_paths = validate_unit_sources(unit, LATEST_SCAN["root"])
        unit["source_validation"] = {"valid": sources_valid, "changed_paths": changed_paths}
        fingerprint = unit.get("spec_fingerprint") or "unfingerprinted"
        decision_key = f"{unit['unit_id']}:{fingerprint}"
        record = decisions.get(decision_key)
        unit["prior_decisions"] = [
            event for event in store.get("audit_log", [])
            if event.get("unit_id") == unit["unit_id"] and event.get("spec_fingerprint") != fingerprint
        ]
        if not sources_valid:
            unit["status"] = "STALE_SOURCE"
            unit.pop("approval", None)
        elif record:
            unit["status"] = record["decision"]
            unit["approval"] = record
        else:
            unit["status"] = "PENDING_REVIEW"
            unit.pop("approval", None)
        unit["generation_authorized"] = False

    counts = {status: sum(1 for unit in units if unit["status"] == status) for status in
              ("PENDING_REVIEW", "APPROVED", "REJECTED", "CHANGES_REQUESTED", "STALE_SOURCE")}
    return {"status": "REVIEW_REQUIRED", "project_root": LATEST_SCAN["root"],
            "unit_count": len(units), "units": units, "status_counts": counts,
            "audit_integrity": "VERIFIED", "generation_enabled": False,
            "approval_policy": "Approval records review intent only. Code generation and database writes remain disabled."}

@app.get("/api/migration-units/{unit_id}")
def migration_unit_detail(unit_id: str):
    result = migration_units()
    for unit in result["units"]:
        if unit["unit_id"] == unit_id:
            return unit
    raise HTTPException(status_code=404, detail="Migration unit not found.")

@app.post("/api/migration-units/{unit_id}/decision")
def decide_migration_unit(unit_id: str, request: UnitDecisionRequest):
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository and generate a migration specification first.")
    result = migration_units()
    unit = next((item for item in result["units"] if item["unit_id"] == unit_id), None)
    if unit is None:
        raise HTTPException(status_code=404, detail="Migration unit not found.")
    if not request.confirm_reviewed:
        raise HTTPException(status_code=422, detail="Confirm that you reviewed the source files, evidence, risks and target mapping.")
    if request.expected_fingerprint != unit.get("spec_fingerprint"):
        raise HTTPException(status_code=409, detail="The migration unit changed since it was displayed. Reload the unit before recording a decision.")
    sources_valid, changed_paths = validate_unit_sources(unit, LATEST_SCAN["root"])
    if not sources_valid:
        raise HTTPException(status_code=409, detail={"message": "Source files changed after analysis. Rescan and regenerate the specification before reviewing.", "changed_paths": changed_paths})

    store_path = approval_store_path(WORKSPACE, LATEST_SCAN["root"])
    try:
        # Lock spans load -> mutate -> atomic replace to prevent lost audit events.
        with approval_store_lock(store_path):
            # Re-check under the same lock as persistence to narrow the source-change race.
            sources_valid, changed_paths = validate_unit_sources(unit, LATEST_SCAN["root"])
            if not sources_valid:
                raise HTTPException(status_code=409, detail={"message": "Source files changed while the decision was being recorded. Rescan and regenerate the specification.", "changed_paths": changed_paths})
            store = load_approval_store(store_path)
            record = apply_decision(unit, store, request.decision, request.actor, request.reason)
            save_approval_store(store_path, store)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"status": record["decision"], "approval": record,
            "generation_authorized": False,
            "message": "Decision recorded with a tamper-evident audit event. This does not enable code generation or authorize database changes."}

@app.get("/api/migration-approvals/audit")
def migration_approval_audit():
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository first.")
    store_path = approval_store_path(WORKSPACE, LATEST_SCAN["root"])
    try:
        with approval_store_lock(store_path):
            store = load_approval_store(store_path)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    events = store.get("audit_log", [])
    return {"audit_log": events, "count": len(events), "integrity": "VERIFIED",
            "store_version": store.get("store_version", 1)}


class AgentModelTestRequest(BaseModel):
    agent_name: str = Field(default="repository_analyst", min_length=1, max_length=80)

class AgentRunRequest(BaseModel):
    enable_llm_review: bool = Field(default=False)

@app.get("/api/agent-system/status")
def agent_system_status():
    """Return available agents and sanitized provider/model routing."""
    config = MODEL_MANAGER.public_config()
    return {
        "system": "CodeBridge Hybrid Multi-Agent Foundation",
        "orchestration": "sequential",
        "agents": [
            {"name": "repository_analyst", "stage": "active", "mode": "deterministic"},
            {"name": "php_understanding", "stage": "active", "mode": "deterministic"},
            {"name": "dependency_analyst", "stage": "active", "mode": "deterministic"},
            {"name": "architecture_analyst", "stage": "active", "mode": "deterministic"},
            {"name": "migration_planner", "stage": "active", "mode": "deterministic"},
            {"name": "backend_migration", "stage": "planned_not_enabled", "mode": "model_assisted"},
            {"name": "frontend_migration", "stage": "planned_not_enabled", "mode": "model_assisted"},
            {"name": "database_guard", "stage": "planned_not_enabled", "mode": "deterministic_guard"},
            {"name": "integration_agent", "stage": "planned_not_enabled", "mode": "model_assisted"},
            {"name": "testing_agent", "stage": "planned_not_enabled", "mode": "deterministic_and_model_assisted"}
        ],
        "model_configuration": config,
        "safety": {"code_generation_enabled": False, "source_write_enabled": False, "database_write_enabled": False}
    }

@app.get("/api/agent-system/providers")
def agent_system_providers():
    return MODEL_MANAGER.list_provider_models()

@app.post("/api/agent-system/reload-model-config")
def reload_agent_model_config():
    try:
        MODEL_MANAGER.reload()
        return {"status": "reloaded", "configuration": MODEL_MANAGER.public_config()}
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/agent-system/test-model")
def test_agent_model(request: AgentModelTestRequest):
    try:
        cfg, provider = MODEL_MANAGER.resolve(request.agent_name)
        output = provider.generate(
            model=cfg.model,
            system="You are a provider connectivity test for CodeBridge AI. Do not generate code or request secrets.",
            prompt="Reply with exactly: CodeBridge model connection successful.",
            timeout=min(cfg.timeout_seconds, 60), max_tokens=64
        )
        return {"status": "connected", "agent": request.agent_name,
                "provider": cfg.provider, "model": cfg.model, "response": output}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Model test failed: {type(exc).__name__}: {exc}")

@app.post("/api/agent-system/run")
def run_agent_system(request: AgentRunRequest):
    if not LATEST_SCAN:
        raise HTTPException(status_code=409, detail="Scan a repository before running the agent workflow.")
    result = AGENT_ORCHESTRATOR.run_analysis(LATEST_SCAN, MODEL_MANAGER, request.enable_llm_review)
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(LATEST_SCAN["root"]).name)[:60] or "repository"
    out = WORKSPACE / f"{name}_multi_agent_report.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["report_file"] = str(out)
    return result
