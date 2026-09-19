"""Detection logic: brute-force, sudo, suspicious activity."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import List, Optional

from .models import Alert, LogEvent

# Suspicious sudo command patterns (persistence / escalation)
SUSPICIOUS_COMMAND_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/bin/bash\s+p'), 'T1548.001'),       # bash -p (privileged)
    (re.compile(r'visudo'), 'T1548.001'),               # modify sudoers
    (re.compile(r'chmod\s+u\+s'), 'T1548.001'),         # setuid
    (re.compile(r'chmod\s+777'), 'T1548.001'),
    (re.compile(r'wget\s+(?!localhost|127\.0\.0\.1)'), 'T1105'),  # download
    (re.compile(r'curl\s+(?!localhost|127\.0\.0\.1)'), 'T1105'),
    (re.compile(r'\bnc\s+'), 'T1105'),                  # netcat
    (re.compile(r'\bncat\s+'), 'T1105'),
    (re.compile(r'/bin/bash\s+-i'), 'T1059'),           # interactive shell
    (re.compile(r'python\s+-c\s+.*socket'), 'T1059'),   # reverse shell
]

OFF_HOURS_START = 22
OFF_HOURS_END = 6


def _in_off_hours(ts: datetime, start: int, end: int) -> bool:
    """Return True if ts.hour is in the off-hours range (wrapping midnight).

    Range is [start, end) — start inclusive, end exclusive.
    """
    h = ts.hour
    if start <= end:
        return start <= h < end
    else:
        # Wraps midnight: e.g. 22 -> 06 means [22, 24) union [0, 6)
        return h >= start or h < end


def brute_force_detector(
    events: List[LogEvent],
    threshold: int = 5,
    window_seconds: int = 300,
    ignore_ips: Optional[List[str]] = None,
) -> List[Alert]:
    """Detect brute-force SSH and compromised IPs."""
    ignore_ips = set(ignore_ips or [])
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        p = ev.parsed
        if p.get('event') in ('failed', 'auth_failure'):
            ip = p.get('src_ip')
            if ip and ip not in ignore_ips:
                by_ip[ip].append(ev)

    alerts: List[Alert] = []

    for ip, ip_events in by_ip.items():
        if len(ip_events) < threshold:
            continue

        ip_events_sorted = sorted(ip_events, key=lambda e: e.timestamp)

        first = ip_events_sorted[0].timestamp
        last = ip_events_sorted[-1].timestamp
        window_note = ''
        if (last - first).total_seconds() <= window_seconds:
            window_note = (
                f' ({len(ip_events_sorted)} failures within '
                f'{window_seconds}s — burst)'
            )

        # Compromise detection: any accepted login from this IP after first failure?
        compromised = False
        accepted_after_fail = None
        first_fail_time = ip_events_sorted[0].timestamp
        for ev in events:
            p = ev.parsed
            if p.get('event') == 'accepted' and p.get('src_ip') == ip:
                if ev.timestamp > first_fail_time:
                    compromised = True
                    accepted_after_fail = ev
                    break

        if compromised and accepted_after_fail:
            alerts.append(Alert(
                severity='critical',
                alert_type='compromised_ip',
                src_ip=ip,
                user=accepted_after_fail.parsed.get('user'),
                count=len(ip_events_sorted),
                first_seen=ip_events_sorted[0].timestamp,
                last_seen=ip_events_sorted[-1].timestamp,
                detail=(
                    f"{len(ip_events_sorted)} failed attempts followed by "
                    f"successful login from {ip}"
                ) + window_note,
                mitre_tactic='T1110.001',
            ))
        else:
            alerts.append(Alert(
                severity='high',
                alert_type='brute_force',
                src_ip=ip,
                count=len(ip_events_sorted),
                first_seen=ip_events_sorted[0].timestamp,
                last_seen=ip_events_sorted[-1].timestamp,
                detail=f"{len(ip_events_sorted)} failed SSH attempts from {ip}" + window_note,
                mitre_tactic='T1110',
            ))

    return alerts


def sudo_detector(
    events: List[LogEvent],
    ignore_users: Optional[List[str]] = None,
) -> List[Alert]:
    """Detect denied sudo, failed sudo auth, suspicious commands."""
    ignore_users = set(ignore_users or [])
    alerts: List[Alert] = []

    denied_by_user: dict[str, list[LogEvent]] = defaultdict(list)
    auth_fail_by_user: dict[str, list[LogEvent]] = defaultdict(list)
    suspicious: list[LogEvent] = []

    for ev in events:
        p = ev.parsed
        if not p:
            continue
        user = p.get('user')
        if user and user in ignore_users:
            continue

        if p.get('event') == 'denied':
            denied_by_user[user].append(ev)
        elif p.get('event') == 'auth_failure' and ev.process == 'sudo':
            auth_fail_by_user[user].append(ev)
        elif p.get('event') == 'command':
            cmd = p.get('command', '')
            for pattern, mitre in SUSPICIOUS_COMMAND_PATTERNS:
                if pattern.search(cmd):
                    suspicious.append(ev)
                    break

    for user, evs in denied_by_user.items():
        evs_sorted = sorted(evs, key=lambda e: e.timestamp)
        alerts.append(Alert(
            severity='medium',
            alert_type='denied_sudo',
            user=user,
            count=len(evs_sorted),
            first_seen=evs_sorted[0].timestamp,
            last_seen=evs_sorted[-1].timestamp,
            detail=(
                f"{len(evs_sorted)} sudo denial(s) for user '{user}' "
                f"(not in sudoers)"
            ),
            mitre_tactic='T1548.001',
        ))

    for user, evs in auth_fail_by_user.items():
        evs_sorted = sorted(evs, key=lambda e: e.timestamp)
        alerts.append(Alert(
            severity='medium',
            alert_type='failed_sudo',
            user=user,
            count=len(evs_sorted),
            first_seen=evs_sorted[0].timestamp,
            last_seen=evs_sorted[-1].timestamp,
            detail=(
                f"{len(evs_sorted)} sudo authentication failure(s) "
                f"for user '{user}'"
            ),
            mitre_tactic='T1110',
        ))

    for ev in suspicious:
        p = ev.parsed
        alerts.append(Alert(
            severity='high',
            alert_type='suspicious_command',
            user=p.get('user'),
            count=1,
            first_seen=ev.timestamp,
            last_seen=ev.timestamp,
            detail=(
                f"Suspicious sudo command by '{p.get('user')}': "
                f"{p.get('command')}"
            ),
            mitre_tactic=_suspicious_mitre(p.get('command', '')),
        ))

    return alerts


def _suspicious_mitre(cmd: str) -> Optional[str]:
    for pattern, mitre in SUSPICIOUS_COMMAND_PATTERNS:
        if pattern.search(cmd):
            return mitre
    return None


def suspicious_activity_detector(
    events: List[LogEvent],
    off_hours_start: int = OFF_HOURS_START,
    off_hours_end: int = OFF_HOURS_END,
    ignore_ips: Optional[List[str]] = None,
) -> List[Alert]:
    """Detect root login, off-hours login, user enumeration, new user first-seen."""
    ignore_ips = set(ignore_ips or [])
    alerts: List[Alert] = []

    accepted_by_user: dict[str, list[LogEvent]] = defaultdict(list)
    invalid_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        p = ev.parsed
        if not p:
            continue

        # Root login
        if p.get('event') == 'accepted' and p.get('user') == 'root':
            alerts.append(Alert(
                severity='high',
                alert_type='root_login',
                user='root',
                src_ip=p.get('src_ip'),
                count=1,
                first_seen=ev.timestamp,
                last_seen=ev.timestamp,
                detail=(
                    f"Root login via SSH from "
                    f"{p.get('src_ip') or 'unknown'}"
                ),
                mitre_tactic='T1078.004',
            ))

        # Off-hours login (any accepted)
        if p.get('event') == 'accepted':
            user = p.get('user')
            accepted_by_user[user].append(ev)
            if _in_off_hours(ev.timestamp, off_hours_start, off_hours_end):
                alerts.append(Alert(
                    severity='low',
                    alert_type='off_hours_login',
                    user=user,
                    src_ip=p.get('src_ip'),
                    count=1,
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                    detail=(
                        f"Successful login by '{user}' at "
                        f"{ev.timestamp.strftime('%H:%M')} "
                        f"(off-hours: {off_hours_start}:00–"
                        f"{off_hours_end}:00)"
                    ),
                    mitre_tactic='T1078',
                ))

        # Invalid user (enumeration tracking)
        if p.get('event') == 'invalid_user':
            ip = p.get('src_ip')
            if ip and ip not in ignore_ips:
                invalid_by_ip[ip].append(ev)

    # User enumeration: 10+ invalid user from one IP
    for ip, evs in invalid_by_ip.items():
        if len(evs) >= 10:
            evs_sorted = sorted(evs, key=lambda e: e.timestamp)
            alerts.append(Alert(
                severity='medium',
                alert_type='user_enumeration',
                src_ip=ip,
                count=len(evs_sorted),
                first_seen=evs_sorted[0].timestamp,
                last_seen=evs_sorted[-1].timestamp,
                detail=(
                    f"{len(evs_sorted)} 'Invalid user' attempts from "
                    f"{ip} — possible user enumeration"
                ),
                mitre_tactic='T1110.001',
            ))

    # New user first-seen: users in accepted that appear only once
    for user, evs in accepted_by_user.items():
        if len(evs) == 1:
            ev = evs[0]
            alerts.append(Alert(
                severity='low',
                alert_type='new_user_first_seen',
                user=user,
                src_ip=ev.parsed.get('src_ip'),
                count=1,
                first_seen=ev.timestamp,
                last_seen=ev.timestamp,
                detail=(
                    f"First-seen user '{user}' logged in successfully "
                    f"from {ev.parsed.get('src_ip') or 'unknown'}"
                ),
                mitre_tactic='T1078',
            ))

    return alerts


def run_detectors(
    events: List[LogEvent],
    config: dict,
) -> List[Alert]:
    """Run all detectors and return combined alerts."""
    threshold = config.get('threshold', 5)
    window = config.get('window_seconds', 300)
    ignore_ips = config.get('ignore_ips', [])
    ignore_users = config.get('ignore_users', [])
    off_start = config.get('off_hours_start', OFF_HOURS_START)
    off_end = config.get('off_hours_end', OFF_HOURS_END)

    alerts: List[Alert] = []
    alerts.extend(
        brute_force_detector(events, threshold, window, ignore_ips)
    )
    alerts.extend(sudo_detector(events, ignore_users))
    alerts.extend(
        suspicious_activity_detector(events, off_start, off_end, ignore_ips)
    )
    return alerts
