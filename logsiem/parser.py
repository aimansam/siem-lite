"""Log parser: syslog RFC 3164 + RFC 3339, plain/gzip/bzip2 files."""

from __future__ import annotations

import bz2
import gzip
import re
from datetime import datetime
from typing import Generator, Optional
from ipaddress import ip_address, AddressValueError

from .models import LogEvent

# ---------------------------------------------------------------------------
# Compiled regexes (module load)
# ---------------------------------------------------------------------------

SYSLOG_HEADER_RFC3164 = re.compile(
    r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+'
)

SYSLOG_HEADER_RFC3339 = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))\s+'
)

PROCESS_PID = re.compile(
    r'((?:sshd(?:-session)?|sudo|su|CRON|pam_unix)'
    r'(?:\[\d+\])?'          # optional [pid]
    r'(?:\([^)]*\))?'        # optional (facility) for pam_unix
    r'):\s+'
)

SSHD_FAILED_PASSWORD = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)'
)

SSHD_ACCEPTED = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?: .*)?$'
)

SSHD_INVALID_USER = re.compile(
    r'Invalid user (\S+) from (\S+)'
)

SUDO_COMMAND = re.compile(
    r'sudo:\s+(\S+)\s+:\s+.*COMMAND=(.*)$'
)

SUDO_DENIED = re.compile(
    r'(\S+)\s+:\s+user NOT in sudoers'
)

SUDO_COMMAND = re.compile(
    r'(\S+)\s+:\s+.*COMMAND=(.*)$'
)

PAM_SSHD_AUTH_FAILURE = re.compile(
    r'pam_unix\(sshd:auth\):\s+authentication failure;.*rhost=(\S+)(?:.*user=(\S+))?'
)

PAM_SUDO_AUTH_FAILURE = re.compile(
    r'pam_unix\(sudo:auth\):\s+authentication failure;.*user=(\S+)'
)

SU_SUCCESS = re.compile(
    r'su:\s+Successful su for root by (\S+)'
)

SU_SUCCESS = re.compile(
    r'su:\s+Successful su for root by (\S+)'
)

CRON_EXEC = re.compile(
    r'CRON\[\d+\]:\s+\((\S+)\)\s+CMD=(.*)$'
)

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def _parse_rfc3164(ts_str: str, year: int) -> Optional[datetime]:
    """Parse `Mon DD HH:MM:SS` (RFC 3164). Returns None on failure."""
    m = re.match(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$', ts_str)
    if not m:
        return None
    month_str, day_str, time_str = m.groups()
    month = MONTHS.get(month_str)
    if month is None:
        return None
    try:
        day = int(day_str)
        h, mi, s = map(int, time_str.split(':'))
    except ValueError:
        return None
    return datetime(year, month, day, h, mi, s)


def _parse_rfc3339(ts_str: str) -> Optional[datetime]:
    """Parse ISO 8601 / RFC 3339 timestamp. Handles Z and ±HH:MM offsets."""
    try:
        s = ts_str
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        # Python 3.7+ fromisoformat handles ±HH:MM
        return datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        return None


def _parse_timestamp(line: str, year: int) -> Optional[datetime]:
    """Detect RFC 3164 vs RFC 3339 and return datetime."""
    # Try RFC 3339 first (starts with a digit year)
    m3339 = SYSLOG_HEADER_RFC3339.match(line)
    if m3339:
        ts_str = m3339.group(1)
        return _parse_rfc3339(ts_str)

    # RFC 3164: Mon DD HH:MM:SS
    m3164 = SYSLOG_HEADER_RFC3164.match(line)
    if m3164:
        ts_str = m3164.group(0).rstrip()
        # Extract just the timestamp portion (first three whitespace-sep tokens)
        parts = ts_str.split()
        if len(parts) >= 3:
            ts_part = ' '.join(parts[:3])
            return _parse_rfc3164(ts_part, year)

    return None


def _parse_process_pid(rest: str) -> tuple[str, Optional[int]]:
    """Extract process name and optional pid from the process field."""
    m = PROCESS_PID.match(rest)
    if not m:
        return 'unknown', None
    proc_full = m.group(1)
    # strip [pid]
    pm = re.match(r'^(.*?)(?:\[(\d+)\])?$', proc_full)
    if pm:
        proc = pm.group(1)
        pid_str = pm.group(2)
        pid = int(pid_str) if pid_str else None
        return proc, pid
    return proc_full, None


def _extract_ip(addr_str: str) -> Optional[str]:
    """Validate and return an IP address string, or None."""
    try:
        ip_address(addr_str)
        return addr_str
    except (AddressValueError, ValueError):
        return None


def _parse_sshd_failed(line_rest: str) -> dict:
    m = SSHD_FAILED_PASSWORD.search(line_rest)
    if m:
        user, src_ip_raw, port_str = m.groups()
        ip = _extract_ip(src_ip_raw)
        return {
            'user': user,
            'src_ip': ip,
            'port': int(port_str),
            'method': 'password',
            'event': 'failed',
        }
    return {}


def _parse_sshd_accepted(line_rest: str) -> dict:
    m = SSHD_ACCEPTED.search(line_rest)
    if m:
        user, src_ip_raw, port_str, *rest = m.groups()
        ip = _extract_ip(src_ip_raw)
        method = 'password' if 'password' in m.group(0) else 'publickey'
        return {
            'user': user,
            'src_ip': ip,
            'port': int(port_str),
            'method': method,
            'event': 'accepted',
        }
    return {}


def _parse_sshd_invalid(line_rest: str) -> dict:
    m = SSHD_INVALID_USER.search(line_rest)
    if m:
        user, src_ip_raw = m.groups()
        ip = _extract_ip(src_ip_raw)
        return {
            'user': user,
            'src_ip': ip,
            'event': 'invalid_user',
        }
    return {}


def _parse_sudo(line_rest: str) -> dict:
    """Parse a sudo: line. Always returns dict with 'user' key."""
    result: dict = {'user': None, 'event': None}

    # Check denied first
    m = SUDO_DENIED.search(line_rest)
    if m:
        result['user'] = m.group(1)
        result['event'] = 'denied'
        return result

    # Check auth failure (pam_unix(sudo:auth))
    m = SUDO_AUTH_FAILURE.search(line_rest)
    if m:
        result['user'] = m.group(1)
        result['event'] = 'auth_failure'
        return result

    # Check COMMAND
    m = SUDO_COMMAND.search(line_rest)
    if m:
        user = m.group(1)
        command = m.group(2)
        result['user'] = user
        result['command'] = command
        result['event'] = 'command'
        # Extract TTY, PWD, USER from the middle
        middle = line_rest.split('COMMAND=', 1)[0]
        for field_match in re.finditer(r'(TTY|PWD|USER)=([^;]+)', middle):
            result[field_match.group(1).lower()] = field_match.group(2).strip()
        return result

    return result


def _parse_pam_sshd(line_rest: str) -> dict:
    m = PAM_SSHD_AUTH_FAILURE.search(line_rest)
    if m:
        src_ip_raw = m.group(1)
        user = m.group(2) or None
        ip = _extract_ip(src_ip_raw) if src_ip_raw else None
        return {'src_ip': ip, 'user': user, 'event': 'auth_failure'}
    return {}


def _parse_su(line_rest: str) -> dict:
    m = SU_SUCCESS.search(line_rest)
    if m:
        return {'user': m.group(1), 'event': 'su_success'}
    return {'user': None, 'event': None}


def _parse_cron(line_rest: str) -> dict:
    m = CRON_EXEC.search(line_rest)
    if m:
        return {'user': m.group(1), 'command': m.group(2), 'event': 'cron'}
    return {}


def parse_line(line: str, source_file: str, line_number: int,
               current_year: int) -> LogEvent:
    """Parse a single syslog line into a LogEvent.

    Returns a LogEvent with process='unknown' and empty parsed dict if no
    pattern matches.
    """
    line = line.rstrip('\n\r')
    if not line:
        # Return a sentinel for empty lines so they're countable but harmless
        return LogEvent(
            timestamp=datetime(current_year, 1, 1),
            hostname='',
            process='unknown',
            raw_message='',
            parsed={},
            source_file=source_file,
            line_number=line_number,
        )

    ts = _parse_timestamp(line, current_year)
    # Default timestamp if we can't parse
    if ts is None:
        ts = datetime(current_year, 1, 1)

    # Extract hostname after timestamp
    hostname = ''
    body = line
    # RFC 3164 header: strip "Mon DD HH:MM:SS hostname "
    m3164 = SYSLOG_HEADER_RFC3164.match(line)
    if m3164:
        # hostname is the 4th group
        hostname = m3164.group(4)
        body = line[m3164.end():]
    else:
        # RFC 3339 header: strip "YYYY-MM-DDTHH:MM:SS hostname "
        m3339 = SYSLOG_HEADER_RFC3339.match(line)
        if m3339:
            rest = line[m3339.end():]
            # hostname is everything up to the next space
            parts = rest.split(None, 1)
            if parts:
                hostname = parts[0]
                body = parts[1] if len(parts) > 1 else ''

    process, pid = _parse_process_pid(body)
    # Strip the process prefix so sub-parsers get clean message
    proc_match = PROCESS_PID.match(body)
    if proc_match:
        body = body[proc_match.end():]

    parsed: dict = {}

    if process in ('sshd', 'sshd-session'):
        # Try failed, then accepted, then invalid
        parsed = _parse_sshd_failed(body)
        if not parsed:
            parsed = _parse_sshd_accepted(body)
        if not parsed:
            parsed = _parse_sshd_invalid(body)
        if not parsed:
            parsed = {'event': 'unknown_sshd'}

    elif process == 'sudo':
        parsed = _parse_sudo(body)

    elif process == 'pam_unix':
        parsed = _parse_pam_sshd(body)
        if not parsed:
            parsed = {'event': 'pam_unknown'}

    elif process == 'su':
        parsed = _parse_su(body)

    elif process == 'CRON':
        parsed = _parse_cron(body)

    else:
        parsed = {}

    return LogEvent(
        timestamp=ts,
        hostname=hostname,
        process=process,
        pid=pid,
        raw_message=line,
        parsed=parsed,
        source_file=source_file,
        line_number=line_number,
    )


def iter_log_file(path: str, current_year: int) -> Generator[LogEvent, None, None]:
    """Yield LogEvent objects from a log file (plain, .gz, .bz2)."""
    opener = open
    if path.endswith('.gz'):
        opener = gzip.open
    elif path.endswith('.bz2'):
        opener = bz2.open

    with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.rstrip('\n\r')
            if not line:
                continue
            yield parse_line(line, path, lineno, current_year)
