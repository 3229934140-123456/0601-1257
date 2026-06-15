import os
import json
from typing import Dict, Optional, Any


DEFAULT_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".logalyzer")
DEFAULT_CONFIG_FILE = os.path.join(DEFAULT_CONFIG_DIR, "config.json")
DEFAULT_PROFILES_DIR = os.path.join(DEFAULT_CONFIG_DIR, "profiles")


class ConfigManager:
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.config_file = os.path.join(self.config_dir, "config.json")
        self.profiles_dir = os.path.join(self.config_dir, "profiles")
        self._config: Dict = {}
        self._ensure_dirs()
        self.load()

    def _ensure_dirs(self):
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.profiles_dir, exist_ok=True)

    def load(self) -> Dict:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    self._config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._config = {}
        if "default_log_paths" not in self._config:
            self._config["default_log_paths"] = []
        if "default_format" not in self._config:
            self._config["default_format"] = "combined"
        if "page_size" not in self._config:
            self._config["page_size"] = 20
        if "highlight_keywords" not in self._config:
            self._config["highlight_keywords"] = []
        if "rules_files" not in self._config:
            self._config["rules_files"] = []
        if "export_dir" not in self._config:
            self._config["export_dir"] = os.path.join(os.path.expanduser("~"), "logalyzer_exports")
        return self._config

    def save(self) -> bool:
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            return True
        except IOError:
            return False

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._config[key] = value

    def get_config(self) -> Dict:
        return dict(self._config)

    def save_profile(self, name: str, params: Dict) -> bool:
        profile_path = os.path.join(self.profiles_dir, f"{name}.json")
        try:
            with open(profile_path, "w", encoding="utf-8") as f:
                json.dump(params, f, indent=2, ensure_ascii=False)
            return True
        except IOError:
            return False

    def load_profile(self, name: str) -> Optional[Dict]:
        profile_path = os.path.join(self.profiles_dir, f"{name}.json")
        if not os.path.exists(profile_path):
            return None
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def list_profiles(self) -> list:
        profiles = []
        if os.path.exists(self.profiles_dir):
            for fname in os.listdir(self.profiles_dir):
                if fname.endswith(".json"):
                    profiles.append(fname[:-5])
        return sorted(profiles)

    def delete_profile(self, name: str) -> bool:
        profile_path = os.path.join(self.profiles_dir, f"{name}.json")
        if os.path.exists(profile_path):
            os.remove(profile_path)
            return True
        return False

    def add_log_path(self, path: str) -> None:
        paths = self._config.get("default_log_paths", [])
        if path not in paths:
            paths.append(path)
            self._config["default_log_paths"] = paths

    def remove_log_path(self, path: str) -> bool:
        paths = self._config.get("default_log_paths", [])
        if path in paths:
            paths.remove(path)
            self._config["default_log_paths"] = paths
            return True
        return False

    def add_highlight_keyword(self, keyword: str) -> None:
        kws = self._config.get("highlight_keywords", [])
        if keyword not in kws:
            kws.append(keyword)
            self._config["highlight_keywords"] = kws

    def remove_highlight_keyword(self, keyword: str) -> bool:
        kws = self._config.get("highlight_keywords", [])
        if keyword in kws:
            kws.remove(keyword)
            self._config["highlight_keywords"] = kws
            return True
        return False

    def add_rules_file(self, filepath: str) -> None:
        files = self._config.get("rules_files", [])
        if filepath not in files:
            files.append(filepath)
            self._config["rules_files"] = files

    def remove_rules_file(self, filepath: str) -> bool:
        files = self._config.get("rules_files", [])
        if filepath in files:
            files.remove(filepath)
            self._config["rules_files"] = files
            return True
        return False
