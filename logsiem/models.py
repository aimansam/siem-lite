"""Data models for logsiem."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Literal, Optional


Severity = Literal["critical", "high", "medium", "low"]

AlertType = str  # brute_force | compromised_ip | failed_sudo | denied_sudo |
#     suspicious_command | root_login | off_hours_login |
#     user_enumeration | new_user_first_seen


@dataclass
class LogEvent:
    timestamp: datetime
    hostname: str
    process: str
    pid: Optional[int] = None
    raw_message: str = ""
    parsed: Dict[str, Any] = field(default_factory=dict)
    source_file: str = ""
    line_number: int = 0

    def __post_init__(self):
        if self.pid is None:
            self.pid = None


@dataclass
class Alert:
    severity: Severity
    alert_type: AlertType
    src_ip: Optional[str] = None
    user: Optional[str] = None
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    detail: str = ""
    mitre_tactic: Optional[str] = None
