"""Configuration defaults and CLI overrides."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


DEFAULTS: Dict[str, Any] = {
    "threshold": 5,
    "window_seconds": 300,
    "off_hours_start": 22,
    "off_hours_end": 6,
    "formats": ["html", "json"],
    "output_dir": "output",
    "ignore_ips": [],
    "ignore_users": [],
}


def build_config(cli_args: Dict[str, Any]) -> Dict[str, Any]:
    """Merge CLI args over defaults."""
    config: Dict[str, Any] = dict(DEFAULTS)
    for key, value in cli_args.items():
        if value is not None:
            config[key] = value
    # Normalize lists
    if isinstance(config.get("ignore_ips"), str):
        config["ignore_ips"] = [config["ignore_ips"]]
    if isinstance(config.get("ignore_users"), str):
        config["ignore_users"] = [config["ignore_users"]]
    return config
