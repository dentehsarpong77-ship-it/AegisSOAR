import os
from pathlib import Path
from typing import Any, Dict, List
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "aegissoar" / "static"

DATA_DIR.mkdir(exist_ok=True)

DB_PATH = os.getenv("AEGIS_DB_PATH", str(DATA_DIR / "aegis.db"))
RULES_FILE = CONFIG_DIR / "rules.yaml"
PLAYBOOKS_FILE = CONFIG_DIR / "playbooks.yaml"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

FIREWALL_SIMULATION_MODE = os.getenv("AEGIS_FIREWALL_SIMULATION", "true").lower() == "true"
WEBHOOK_ALERT_URL = os.getenv("AEGIS_WEBHOOK_URL", "")


def load_yaml_rules() -> List[Dict[str, Any]]:
    if not RULES_FILE.exists():
        return []
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
        return data.get("rules", [])


def load_yaml_playbooks() -> List[Dict[str, Any]]:
    if not PLAYBOOKS_FILE.exists():
        return []
    with open(PLAYBOOKS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
        return data.get("playbooks", [])
