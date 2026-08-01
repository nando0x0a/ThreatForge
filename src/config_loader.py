#!/usr/bin/env python3
import os
from pathlib import Path

import yaml

CONFIG_PATH = Path(os.getenv("VULN_SKILL_CONFIG", "/opt/vuln-skill/config/vuln-skill.yaml"))

_config = None


def load_config() -> dict:
    global _config
    if _config is not None:
        return _config
    with open(CONFIG_PATH) as f:
        _config = yaml.safe_load(f)
    return _config
