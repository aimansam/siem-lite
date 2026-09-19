"""CLI entry point: argument parsing + orchestration."""

from __future__ import annotations

import argparse
import glob
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import build_config, DEFAULTS
from .detector import run_detectors
from .models import LogEvent
from .parser import iter_log_file
from .report import generate_report


def _expand_paths(paths: list[str]) -> list[str]:
    """Expand globs in paths. Non-glob paths passed through as-is."""
    result: list[str] = []
    for p in paths:
        if '*' in p or '?' in p or '[' in p:
            expanded = sorted(glob.glob(p))
            if not expanded:
                print(f"Warning: glob pattern '{p}' matched no files", file=sys.stderr)
            result.extend(expanded)
        else:
            result.append(p)
    return result


def _parse_datetime_filter(s: Optional[str]) -> Optional[datetime]:
    """Parse --since/--until value."""
    if not s:
        return None
    for fmt in (
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M',
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    print(f"Warning: couldn't parse datetime '{s}', ignoring filter", file=sys.stderr)
    return None


def _filter_events(
    events: list[LogEvent],
    since: Optional[datetime],
    until: Optional[datetime],
    host: Optional[str],
) -> list[LogEvent]:
    """Apply time and host filters."""
    filtered: list[LogEvent] = []
    for ev in events:
        if since and ev.timestamp < since:
            continue
        if until and ev.timestamp > until:
            continue
        if host and ev.hostname and ev.hostname != host:
            continue
        filtered.append(ev)
    return filtered


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='logsiem',
        description='SIEM-lite log analysis: detect brute-force SSH, '
                    'failed sudo, and suspicious activity from auth logs.',
    )
    sub = parser.add_subparsers(dest='command')

    run_parser = sub.add_parser('run', help='Analyze log files and generate reports')
    run_parser.add_argument(
        'log_paths',
        nargs='+',
        help='One or more log file paths (globs supported)',
    )
    run_parser.add_argument(
        '--threshold', type=int, default=DEFAULTS['threshold'],
        help=f"Failed auth threshold for brute-force alert (default: {DEFAULTS['threshold']})",
    )
    run_parser.add_argument(
        '--window', type=int, default=DEFAULTS['window_seconds'],
        help=f"Burst window in seconds (default: {DEFAULTS['window_seconds']})",
    )
    run_parser.add_argument(
        '--format', choices=['html', 'json', 'csv', 'events_csv'],
        nargs='+', default=list(DEFAULTS['formats']),
        help=f"Output formats (default: {', '.join(DEFAULTS['formats'])})",
    )
    run_parser.add_argument(
        '--output-dir', type=str, default=DEFAULTS['output_dir'],
        help=f"Directory for reports (default: {DEFAULTS['output_dir']})",
    )
    run_parser.add_argument(
        '--since', type=str, default=None,
        help="Filter events after this time (ISO 8601)",
    )
    run_parser.add_argument(
        '--until', type=str, default=None,
        help="Filter events before this time (ISO 8601)",
    )
    run_parser.add_argument(
        '--host', type=str, default=None,
        help="Filter to a single hostname",
    )
    run_parser.add_argument(
        '--ignore-ip', type=str, action='append', default=[],
        help="IP to ignore (repeatable)",
    )
    run_parser.add_argument(
        '--ignore-user', type=str, action='append', default=[],
        help="User to ignore (repeatable)",
    )
    run_parser.add_argument(
        '--list-formats', action='store_true',
        help="Print available output formats and exit",
    )
    run_parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help="Increase console output detail",
    )

    args = parser.parse_args(argv)

    if args.command == 'run':
        if args.list_formats:
            print("Available output formats: html, json, csv, events_csv")
            return 0

        # Expand globs
        paths = _expand_paths(args.log_paths)
        if not paths:
            print("Error: no log files found", file=sys.stderr)
            return 1

        # Validate existence
        missing = [p for p in paths if not Path(p).exists()]
        if missing:
            for m in missing:
                print(f"Error: file not found: {m}", file=sys.stderr)
            return 1

        # Build config
        cli_config = {
            'threshold': args.threshold,
            'window_seconds': args.window,
            'formats': args.format,
            'output_dir': args.output_dir,
            'ignore_ips': args.ignore_ip or [],
            'ignore_users': args.ignore_user or [],
            'files_analyzed': paths,
        }
        config = build_config(cli_config)

        if args.verbose:
            print(f"Analyzing {len(paths)} file(s): {', '.join(paths)}", file=sys.stderr)

        # Parse
        current_year = datetime.now().year
        all_events: list[LogEvent] = []
        for path in paths:
            try:
                for ev in iter_log_file(path, current_year):
                    all_events.append(ev)
            except Exception as e:
                print(f"Warning: error reading {path}: {e}", file=sys.stderr)

        if args.verbose:
            print(f"Parsed {len(all_events)} events", file=sys.stderr)

        # Filter
        since = _parse_datetime_filter(args.since)
        until = _parse_datetime_filter(args.until)
        filtered = _filter_events(all_events, since, until, args.host)

        if args.verbose:
            print(f"After filters: {len(filtered)} events", file=sys.stderr)
            if since:
                print(f"  since: {since}", file=sys.stderr)
            if until:
                print(f"  until: {until}", file=sys.stderr)
            if args.host:
                print(f"  host: {args.host}", file=sys.stderr)

        # Detect
        alerts = run_detectors(filtered, config)

        if args.verbose:
            sev_counts: dict[str, int] = {}
            for a in alerts:
                sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
            print(f"Alerts: {len(alerts)} total", file=sys.stderr)
            for sev in ('critical', 'high', 'medium', 'low'):
                if sev_counts.get(sev):
                    print(f"  {sev}: {sev_counts[sev]}", file=sys.stderr)

        # Also count events for the stats (use filtered set)
        config['files_analyzed'] = paths

        # Generate reports
        try:
            generated = generate_report(filtered, alerts, config, args.output_dir, args.format)
        except Exception as e:
            print(f"Error generating reports: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return 1

        # Console summary
        print(f"\nDone. Generated {len(generated)} report(s) in {args.output_dir}/:")
        for fmt, path in generated.items():
            print(f"  {fmt}: {path}")

        return 0

    # No command / help
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
