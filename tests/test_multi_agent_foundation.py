import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.providers.manager import ModelManager
from app.agents.orchestrator import AgentOrchestrator

class MultiAgentFoundationTests(unittest.TestCase):
    def _manager(self, data):
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name) / "models.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return temp, ModelManager(path)

    def test_default_model_inherits_active_ollama_provider(self):
        temp, manager = self._manager({
            "active_provider": "ollama",
            "providers": {"ollama": {"type": "ollama", "base_url": "http://localhost:11434", "default_model": "qwen-coder:8b"}},
            "agent_models": {}, "agent_providers": {}
        })
        try:
            cfg, provider = manager.resolve("php_understanding")
            self.assertEqual(cfg.model, "qwen-coder:8b")
            self.assertEqual(cfg.provider, "ollama")
        finally:
            temp.cleanup()

    def test_agent_can_override_provider_and_model(self):
        temp, manager = self._manager({
            "active_provider": "ollama",
            "providers": {
                "ollama": {"type": "ollama", "base_url": "http://localhost:11434", "default_model": "local:3b"},
                "openai": {"type": "openai_compatible", "base_url": "https://api.openai.com/v1", "api_key_env": "OPENAI_API_KEY", "default_model": "gpt-example"}
            },
            "agent_providers": {"architecture_analyst": "openai"},
            "agent_models": {"architecture_analyst": "gpt-example"}
        })
        try:
            cfg, provider = manager.resolve("architecture_analyst")
            self.assertEqual(cfg.provider, "openai")
            self.assertEqual(cfg.model, "gpt-example")
        finally:
            temp.cleanup()

    def test_public_config_never_contains_api_key_value(self):
        temp, manager = self._manager({
            "active_provider": "openai",
            "providers": {"openai": {"type": "openai_compatible", "base_url": "https://api.openai.com/v1", "api_key_env": "TEST_SECRET_KEY", "default_model": "test"}},
            "agent_models": {}
        })
        try:
            with patch.dict("os.environ", {"TEST_SECRET_KEY": "do-not-leak-this"}):
                rendered = json.dumps(manager.public_config())
                self.assertNotIn("do-not-leak-this", rendered)
                self.assertIn('"api_key_configured": true', rendered)
        finally:
            temp.cleanup()

    def test_orchestrator_has_sequential_deterministic_analysis_agents(self):
        orchestrator = AgentOrchestrator()
        self.assertEqual([a.name for a in orchestrator.agents], [
            "repository_analyst", "php_understanding", "dependency_analyst",
            "architecture_analyst", "migration_planner"
        ])
        self.assertTrue(all(a.mode == "deterministic" for a in orchestrator.agents))

    def test_orchestrator_never_enables_generation(self):
        # A minimal scan fixture with no PHP files is sufficient to exercise the workflow.
        scan = {"root": ".", "file_count": 0, "php_file_count": 0, "php_files": [], "files": [], "warnings": [], "framework_hints": []}
        result = AgentOrchestrator().run_analysis(scan)
        self.assertFalse(result["generation_enabled"])
        self.assertFalse(result["safety"]["source_project_write"])
        self.assertFalse(result["safety"]["database_write"])

    def test_optional_llm_review_is_advisory_and_does_not_enable_generation(self):
        class FakeConfig:
            provider = "ollama"
            model = "test-model"
            timeout_seconds = 10
            max_tokens = 100
        class FakeProvider:
            def generate(self, **kwargs):
                return "Review note: verify route coverage."
        class FakeManager:
            def resolve(self, agent_name):
                return FakeConfig(), FakeProvider()
        scan = {"root": ".", "file_count": 0, "php_file_count": 0, "php_files": [], "files": [], "warnings": [], "framework_hints": []}
        result = AgentOrchestrator().run_analysis(scan, FakeManager(), enable_llm_review=True)
        self.assertTrue(result["llm_review_enabled"])
        self.assertFalse(result["generation_enabled"])
        self.assertTrue(all("advisory_review" in item for item in result["agents"]))
        self.assertTrue(all(item["advisory_review"]["authoritative"] is False for item in result["agents"]))

if __name__ == "__main__":
    unittest.main()
