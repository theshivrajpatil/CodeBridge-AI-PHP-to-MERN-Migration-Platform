"""Small, pluggable path/marker adapters. They never replace universal PHP analysis."""
from .base import Detection

class LaravelAdapter:
    adapter_id = "laravel"
    display_name = "Laravel"
    def detect(self, paths):
        evidence = [p for p in ("artisan", "bootstrap/app.php", "routes/web.php") if p in paths]
        if "artisan" in paths or ("bootstrap/app.php" in paths and "routes/web.php" in paths):
            return Detection("Laravel", "HIGH", evidence, self.adapter_id)
        return None
    def classify(self, p):
        rules = [
            ("routes/", "Routes"), ("app/http/controllers/", "Controllers"),
            ("app/http/middleware/", "Middleware"), ("app/models/", "Models"),
            ("app/services/", "Services"), ("app/repositories/", "Repositories"),
            ("database/migrations/", "Database migrations"), ("database/seeders/", "Database seeders"),
            ("database/factories/", "Test data factories"), ("resources/views/", "Templates"),
            ("tests/", "Tests"), ("config/", "Configuration"), ("bootstrap/", "Bootstrap"),
            ("app/providers/", "Framework providers"), ("app/jobs/", "Background jobs"),
            ("app/events/", "Events"), ("app/listeners/", "Event listeners")]
        return _prefix_classify(p, rules, "Laravel path convention")

class SymfonyAdapter:
    adapter_id = "symfony"
    display_name = "Symfony"
    def detect(self, paths):
        ev = [p for p in ("symfony.lock", "config/bundles.php", "bin/console") if p in paths]
        if len(ev) >= 2 or ("config/bundles.php" in paths and any(p.startswith("src/controller/") for p in paths)):
            return Detection("Symfony", "HIGH" if len(ev) >= 2 else "MEDIUM", ev, self.adapter_id)
        return None
    def classify(self, p):
        return _prefix_classify(p, [("src/controller/", "Controllers"), ("src/entity/", "Models / entities"),
            ("src/repository/", "Repositories"), ("src/service/", "Services"), ("src/eventsubscriber/", "Middleware / event subscribers"),
            ("templates/", "Templates"), ("config/", "Configuration"), ("migrations/", "Database migrations"),
            ("tests/", "Tests"), ("public/", "Public entrypoints / assets")], "Symfony path convention")

class CodeIgniterAdapter:
    adapter_id = "codeigniter"
    display_name = "CodeIgniter"
    def detect(self, paths):
        ev = [p for p in ("spark", "application/config/config.php", "system/core/codeigniter.php") if p in paths]
        if "spark" in paths or ("application/config/config.php" in paths and any(p.startswith("application/controllers/") for p in paths)):
            return Detection("CodeIgniter", "HIGH", ev or ["CodeIgniter directory markers"], self.adapter_id)
        return None
    def classify(self, p):
        return _prefix_classify(p, [("app/controllers/", "Controllers"), ("application/controllers/", "Controllers"),
            ("app/models/", "Models / entities"), ("application/models/", "Models / entities"),
            ("app/config/", "Configuration"), ("application/config/", "Configuration"),
            ("app/views/", "Templates"), ("application/views/", "Templates"), ("tests/", "Tests")], "CodeIgniter path convention")

class WordPressAdapter:
    adapter_id = "wordpress"
    display_name = "WordPress"
    def detect(self, paths):
        ev = [p for p in ("wp-load.php", "wp-settings.php", "wp-includes/version.php") if p in paths]
        if len(ev) >= 2: return Detection("WordPress", "HIGH", ev, self.adapter_id)
        return None
    def classify(self, p):
        if p.startswith(("wp-admin/", "wp-includes/")): return {"group": "CMS core", "confidence": "HIGH", "reason": "WordPress core path"}
        if p.startswith("wp-content/plugins/"): return {"group": "CMS plugins", "confidence": "MEDIUM", "reason": "WordPress plugin path"}
        if p.startswith("wp-content/themes/"): return {"group": "CMS themes / templates", "confidence": "MEDIUM", "reason": "WordPress theme path"}
        return None

class GenericPHPAdapter:
    adapter_id = "generic_php"
    display_name = "PHP (framework not confirmed)"
    def detect(self, paths):
        if "composer.json" in paths: return Detection(self.display_name, "LOW", ["composer.json; framework not confirmed"], self.adapter_id)
        return Detection("Core PHP / Unknown", "LOW", [], self.adapter_id)
    def classify(self, p):
        rules = [("/controllers/", "Controllers"), ("/controller/", "Controllers"), ("/models/", "Models / entities"),
            ("/entities/", "Models / entities"), ("/services/", "Services"), ("/repositories/", "Repositories"),
            ("/middleware/", "Middleware"), ("/routes/", "Routes"), ("/views/", "Templates"),
            ("/templates/", "Templates"), ("/migrations/", "Database migrations"), ("/tests/", "Tests"),
            ("/config/", "Configuration"), ("/public/", "Public entrypoints / assets")]
        return _contains_classify(p, rules, "Generic PHP naming/path convention")

def _prefix_classify(path, rules, reason):
    for prefix, group in rules:
        if path.startswith(prefix): return {"group": group, "confidence": "HIGH", "reason": reason}
    return None

def _contains_classify(path, rules, reason):
    normalized = "/" + path
    for fragment, group in rules:
        if fragment in normalized: return {"group": group, "confidence": "LOW", "reason": reason}
    return None

ADAPTERS = [LaravelAdapter(), SymfonyAdapter(), CodeIgniterAdapter(), WordPressAdapter(), GenericPHPAdapter()]
