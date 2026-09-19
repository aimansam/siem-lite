"""Report generation: HTML (Jinja2 + Bokeh), JSON, CSV."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import Alert, LogEvent

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def _default_serializer(obj: Any) -> Any:
    """JSON serializer for non-serializable types (datetime)."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f'Object of type {type(obj).__name__} is not JSON serializable')


def compute_stats(events: List[LogEvent], alerts: List[Alert]) -> Dict[str, Any]:
    """Compute summary stats."""
    by_severity: Dict[str, int] = {}
    for a in alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1

    ips: set[str] = set()
    users: set[str] = set()
    for ev in events:
        p = ev.parsed
        ip = p.get('src_ip')
        if ip:
            ips.add(ip)
        user = p.get('user')
        if user:
            users.add(user)
    # Also from alerts
    for a in alerts:
        if a.src_ip:
            ips.add(a.src_ip)
        if a.user:
            users.add(a.user)

    return {
        'total_events': len(events),
        'total_alerts': len(alerts),
        'by_severity': {
            'critical': by_severity.get('critical', 0),
            'high': by_severity.get('high', 0),
            'medium': by_severity.get('medium', 0),
            'low': by_severity.get('low', 0),
        },
        'unique_source_ips': len(ips),
        'unique_users': len(users),
    }


def generate_json(
    events: List[LogEvent],
    alerts: List[Alert],
    stats: Dict[str, Any],
    config: Dict[str, Any],
    output_path: str,
    pretty: bool = False,
) -> None:
    """Write a JSON report."""
    report: Dict[str, Any] = {
        'events': [
            {
                'timestamp': e.timestamp.isoformat(),
                'hostname': e.hostname,
                'process': e.process,
                'pid': e.pid,
                'raw_message': e.raw_message,
                'parsed': e.parsed,
                'source_file': e.source_file,
                'line_number': e.line_number,
            }
            for e in events
        ],
        'alerts': [
            {
                'severity': a.severity,
                'alert_type': a.alert_type,
                'src_ip': a.src_ip,
                'user': a.user,
                'count': a.count,
                'first_seen': a.first_seen.isoformat() if a.first_seen else None,
                'last_seen': a.last_seen.isoformat() if a.last_seen else None,
                'detail': a.detail,
                'mitre_tactic': a.mitre_tactic,
            }
            for a in alerts
        ],
        'stats': stats,
        'config': {
            'threshold': config.get('threshold', 5),
            'window_seconds': config.get('window_seconds', 300),
            'files_analyzed': list(config.get('files_analyzed', [])),
            'time_range': {
                'start': _first_ts(events),
                'end': _last_ts(events),
            },
        },
    }

    indent = 2 if pretty else None
    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, indent=indent, default=_default_serializer)


def generate_csv(
    alerts: List[Alert],
    output_path: str,
) -> None:
    """Write a CSV report of alerts."""
    if not alerts:
        # Write header only
        with open(output_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow([
                'severity', 'alert_type', 'src_ip', 'user', 'count',
                'first_seen', 'last_seen', 'detail', 'mitre_tactic',
            ])
        return

    with open(output_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow([
            'severity', 'alert_type', 'src_ip', 'user', 'count',
            'first_seen', 'last_seen', 'detail', 'mitre_tactic',
        ])
        for a in alerts:
            writer.writerow([
                a.severity,
                a.alert_type,
                a.src_ip or '',
                a.user or '',
                a.count,
                a.first_seen.isoformat() if a.first_seen else '',
                a.last_seen.isoformat() if a.last_seen else '',
                a.detail,
                a.mitre_tactic or '',
            ])


def generate_events_csv(
    events: List[LogEvent],
    output_path: str,
) -> None:
    """Write a CSV of all events."""
    with open(output_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow([
            'timestamp', 'hostname', 'process', 'user', 'src_ip',
            'port', 'message',
        ])
        for e in events:
            p = e.parsed
            writer.writerow([
                e.timestamp.isoformat(),
                e.hostname,
                e.process,
                p.get('user', ''),
                p.get('src_ip', ''),
                p.get('port', ''),
                e.raw_message,
            ])


def _first_ts(events: List[LogEvent]) -> Optional[str]:
    if not events:
        return None
    return min(e.timestamp for e in events).isoformat()


def _last_ts(events: List[LogEvent]) -> Optional[str]:
    if not events:
        return None
    return max(e.timestamp for e in events).isoformat()


# ---------------------------------------------------------------------------
# HTML + Bokeh (optional deps)
# ---------------------------------------------------------------------------

def _has_viz_deps() -> bool:
    try:
        import bokeh  # noqa: F401
        import jinja2  # noqa: F401
        return True
    except ImportError:
        return False


_VIZ_AVAILABLE = _has_viz_deps()


def generate_html(
    events: List[LogEvent],
    alerts: List[Alert],
    stats: Dict[str, Any],
    config: Dict[str, Any],
    output_path: str,
) -> bool:
    """Generate HTML report. Returns True if Bokeh timeline was embedded."""
    if not _VIZ_AVAILABLE:
        # Fall back to a basic HTML without Bokeh
        _generate_html_basic(events, alerts, stats, config, output_path)
        return False

    return _generate_html_bokeh(events, alerts, stats, config, output_path)


def _generate_html_basic(
    events: List[LogEvent],
    alerts: List[Alert],
    stats: Dict[str, Any],
    config: Dict[str, Any],
    output_path: str,
) -> None:
    """HTML report without Bokeh (stdlib only)."""
    html = _html_template(
        stats=stats,
        alerts=alerts,
        config=config,
        bokeh_timeline='',
        alert_rows=_alert_rows_html(alerts),
        has_viz=False,
    )
    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)


def _generate_html_bokeh(
    events: List[LogEvent],
    alerts: List[LogEvent],
    stats: Dict[str, Any],
    config: Dict[str, Any],
    output_path: str,
) -> bool:
    """HTML report with Bokeh timeline."""
    import bokeh
    import bokeh.plotting
    from bokeh.embed import file_html as bokeh_file_html
    from bokeh.resources import CDN
    from bokeh.models import (
        ColumnDataSource,
        HoverTool,
        CategoricalColorMapper,
        Div,
    )
    from bokeh.layouts import column
    import jinja2

    # Build timeline data
    timeline_events: list[dict[str, Any]] = []

    for ev in events:
        p = ev.parsed
        event_type = p.get('event', 'unknown')
        color = _event_color(event_type)
        label = _event_label(ev)
        detail = _event_detail(ev)
        timeline_events.append({
            'timestamp': ev.timestamp,
            'color': color,
            'label': label,
            'detail': detail,
            'type': event_type,
            'user': p.get('user', ''),
            'src_ip': p.get('src_ip', ''),
        })

    # Also add alert markers
    for a in alerts:
        ts = a.first_seen or datetime.now()
        color = _severity_color(a.severity)
        timeline_events.append({
            'timestamp': ts,
            'color': color,
            'label': f"ALERT: {a.alert_type}",
            'detail': a.detail,
            'type': f'alert_{a.severity}',
            'user': a.user or '',
            'src_ip': a.src_ip or '',
        })

    if not timeline_events:
        timeline_events = [{
            'timestamp': datetime.now(),
            'color': '#888888',
            'label': 'No events',
            'detail': '',
            'type': 'none',
            'user': '',
            'src_ip': '',
        }]

    source = ColumnDataSource(data={
        'timestamp': [e['timestamp'] for e in timeline_events],
        'color': [e['color'] for e in timeline_events],
        'label': [e['label'] for e in timeline_events],
        'detail': [e['detail'] for e in timeline_events],
        'type': [e['type'] for e in timeline_events],
        'user': [e['user'] for e in timeline_events],
        'src_ip': [e['src_ip'] for e in timeline_events],
    })

    # Time-range-aware x_range
    min_ts = min(e['timestamp'] for e in timeline_events)
    max_ts = max(e['timestamp'] for e in timeline_events)
    span = (max_ts - min_ts).total_seconds()
    if span < 60:
        span = 60

    p_figure = bokeh.plotting.figure(
        title='Event Timeline',
        x_axis_type='datetime',
        x_range=(min_ts, max_ts),
        height=280,
        width=900,
        tools='pan,box_zoom,wheel_zoom,reset,save',
        toolbar_location='above',
    )

    p_figure.circle(
        'timestamp',
        1,
        source=source,
        size=10,
        color='color',
        alpha=0.85,
        legend_group='type',
    )

    # Hover tool
    hover = HoverTool(
        tooltips=[
            ('Time', '@timestamp{(%Y-%m-%d %H:%M:%S)}'),
            ('Type', '@type'),
            ('Label', '@label'),
            ('Detail', '@detail'),
            ('User', '@user'),
            ('Source IP', '@src_ip'),
        ],
        mode='mouse',
    )
    p_figure.add_tools(hover)

    p_figure.legend.location = 'top_left'
    p_figure.legend.title = 'Event types'
    p_figure.xaxis.axis_label = 'Time'
    p_figure.yaxis.visible = False
    p_figure.ygrid.visible = False

    # Legend overrides for alert rows
    p_figure.legend.label_text_font_size = '10pt'

    html_plot = bokeh_file_html(
        column(p_figure),
        CDN,
        'LogSIEM Timeline',
    )

    # Alert summary rows HTML
    alert_rows_html = _alert_rows_html(alerts)

    html = _html_template(
        stats=stats,
        alerts=alerts,
        config=config,
        bokeh_timeline=html_plot,
        alert_rows=alert_rows_html,
        has_viz=True,
    )

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)

    return True


def _event_color(event_type: str) -> str:
    colors = {
        'failed': '#e74c3c',          # red
        'accepted': '#2ecc71',        # green
        'denied': '#f39c12',          # amber
        'auth_failure': '#e67e22',    # amber-ish
        'command': '#f39c12',         # amber (sudo)
        'invalid_user': '#9b59b6',    # purple
        'su_success': '#8e44ad',      # purple
        'cron': '#3498db',            # blue
        'unknown_sshd': '#95a5a6',
        'pam_unknown': '#95a5a6',
        'alert_critical': '#c0392b',
        'alert_high': '#e74c3c',
        'alert_medium': '#f39c12',
        'alert_low': '#3498db',
    }
    return colors.get(event_type, '#95a5a6')


def _severity_color(severity: str) -> str:
    return {
        'critical': '#c0392b',
        'high': '#e74c3c',
        'medium': '#f39c12',
        'low': '#3498db',
    }.get(severity, '#95a5a6')


def _event_label(ev: LogEvent) -> str:
    p = ev.parsed
    et = p.get('event', 'unknown')
    user = p.get('user', '')
    ip = p.get('src_ip', '')
    if et == 'failed':
        return f"SSH fail: {user}"
    elif et == 'accepted':
        return f"SSH success: {user}"
    elif et == 'denied':
        return f"Sudo denied: {user}"
    elif et == 'auth_failure':
        return f"Auth failure: {user or ip}"
    elif et == 'command':
        return f"Sudo cmd: {user}"
    elif et == 'invalid_user':
        return f"Invalid user: {user}"
    elif et == 'su_success':
        return f"SU success: {user}"
    elif et == 'cron':
        return f"CRON: {user}"
    return f"{ev.process}: {ev.raw_message[:40]}"


def _event_detail(ev: LogEvent) -> str:
    p = ev.parsed
    parts = []
    user = p.get('user', '')
    ip = p.get('src_ip', '')
    port = p.get('port', '')
    cmd = p.get('command', '')
    if user:
        parts.append(f"user={user}")
    if ip:
        parts.append(f"src_ip={ip}")
    if port:
        parts.append(f"port={port}")
    if cmd:
        parts.append(f"command={cmd}")
    return ', '.join(parts) if parts else ev.raw_message[:80]


def _alert_rows_html(alerts: List[Alert]) -> str:
    """Generate HTML table rows for alerts, grouped by severity."""
    if not alerts:
        return '<tr><td colspan="5" style="text-align:center;color:#888;">No alerts generated.</td></tr>'

    rows = []
    for a in alerts:
        sev_color = _severity_color(a.severity)
        ip_cell = (
            f'<a href="https://ipinfo.io/{a.src_ip}"'
            f' target="_blank" rel="noopener">{a.src_ip}</a>'
            if a.src_ip else '—'
        )
        user_cell = a.user or '—'
        rows.append(f'''<tr style="border-left:4px solid {sev_color};">
            <td><span class="badge badge-{a.severity}">{a.severity}</span></td>
            <td><code>{a.alert_type}</code></td>
            <td>{ip_cell}</td>
            <td><code>{user_cell}</code></td>
            <td>{a.count}</td>
            <td title="{a.first_seen.isoformat() if a.first_seen else ''}">{a.first_seen.strftime('%Y-%m-%d %H:%M') if a.first_seen else '—'}</td>
            <td>{a.detail}</td>
        </tr>''')
    return '\n'.join(rows)


def _html_template(
    stats: Dict[str, Any],
    alerts: List[Alert],
    config: Dict[str, Any],
    bokeh_timeline: str,
    alert_rows: str,
    has_viz: bool,
) -> str:
    """Render the full HTML report."""
    sev = stats.get('by_severity', {})
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogSIEM — Analysis Report</title>
<style>
  :root {{
    --bg: #0b0b12;
    --surface: #13131f;
    --border: #2a2a3e;
    --text: #d0d0e0;
    --muted: #6b6b80;
    --critical: #e74c3c;
    --high: #e67e22;
    --medium: #f1c40f;
    --low: #3498db;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
      "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding: 24px;
    max-width: 1100px;
    margin: 0 auto;
  }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color: var(--muted); font-size: 13px; margin-bottom: 20px; }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
    margin-bottom: 20px;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
  }}
  .card .num {{
    font-size: 24px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }}
  .card .lbl {{
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .card.alert {{ border-top: 3px solid var(--critical); }}
  .card.events {{ border-top: 3px solid #2ecc71; }}
  .card.ips {{ border-top: 3px solid #3498db; }}
  .card.users {{ border-top: 3px solid #9b59b6; }}
  h2 {{
    font-size: 15px;
    margin: 18px 0 8px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 600;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }}
  th, td {{
    padding: 8px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    vertical-align: top;
  }}
  th {{
    background: rgba(255,255,255,0.03);
    color: var(--muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    position: sticky;
    top: 0;
  }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{
    display: inline-block;
    padding: 1px 7px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }}
  .badge-critical {{ background: rgba(231,76,60,0.2); color: var(--critical); }}
  .badge-high {{ background: rgba(230,126,34,0.2); color: var(--high); }}
  .badge-medium {{ background: rgba(241,196,15,0.15); color: var(--medium); }}
  .badge-low {{ background: rgba(52,152,219,0.2); color: var(--low); }}
  code {{
    background: rgba(255,255,255,0.06);
    padding: 1px 5px;
    border-radius: 3px;
    font-family: "SF Mono", "Fira Code", "Consolas", monospace;
    font-size: 12px;
  }}
  pre {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    overflow-x: auto;
    font-size: 12px;
    color: var(--text);
    margin-top: 8px;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  .config {{
    margin-top: 16px;
    padding: 10px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 12px;
  }}
  .config h2 {{ margin-top: 0; }}
  .timeline-wrap {{
    margin: 16px 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
  }}
  .no-viz-note {{
    color: var(--muted);
    font-style: italic;
    font-size: 12px;
    padding: 8px 0;
  }}
  a {{ color: var(--low); }}
  .section {{ margin-bottom: 24px; }}
</style>
</head>
<body>

<h1>LogSIEM — Log Analysis Report</h1>
<div class="subtitle">
  Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot;
  {len(config.get('files_analyzed', []))} file(s) analyzed
</div>

<div class="cards">
  <div class="card events">
    <div class="num">{stats.get('total_events', 0)}</div>
    <div class="lbl">Events Parsed</div>
  </div>
  <div class="card alert">
    <div class="num">{stats.get('total_alerts', 0)}</div>
    <div class="lbl">Total Alerts</div>
  </div>
  <div class="card">
    <div class="num" style="color:var(--critical)">{sev.get('critical', 0)}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="card">
    <div class="num" style="color:var(--high)">{sev.get('high', 0)}</div>
    <div class="lbl">High</div>
  </div>
  <div class="card">
    <div class="num" style="color:var(--medium)">{sev.get('medium', 0)}</div>
    <div class="lbl">Medium</div>
  </div>
  <div class="card">
    <div class="num" style="color:var(--low)">{sev.get('low', 0)}</div>
    <div class="lbl">Low</div>
  </div>
  <div class="card ips">
    <div class="num">{stats.get('unique_source_ips', 0)}</div>
    <div class="lbl">Unique Source IPs</div>
  </div>
  <div class="card users">
    <div class="num">{stats.get('unique_users', 0)}</div>
    <div class="lbl">Unique Users</div>
  </div>
</div>

<div class="timeline-wrap">
  <h2>Timeline</h2>
  {bokeh_timeline if has_viz else '<div class="no-viz-note">Bokeh not available — install logsiem[viz] for the interactive timeline.</div>'}
</div>

<div class="section">
  <h2>Alert Summary ({len(alerts)} alert(s))</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Type</th>
        <th>Source IP</th>
        <th>User</th>
        <th>Count</th>
        <th>First Seen</th>
        <th>Detail</th>
      </tr>
    </thead>
    <tbody>
      {alert_rows}
    </tbody>
  </table>
</div>

<div class="config">
  <h2>Configuration</h2>
  <pre>{
    json.dumps({
      "threshold": config.get("threshold", 5),
      "window_seconds": config.get("window_seconds", 300),
      "off_hours": f"{config.get('off_hours_start', 22)}:00-{config.get('off_hours_end', 6)}:00",
      "files_analyzed": config.get("files_analyzed", []),
      "formats_requested": config.get("formats", []),
      "ignore_ips": config.get("ignore_ips", []),
      "ignore_users": config.get("ignore_users", []),
    }, indent=2)
  }</pre>
</div>

</body>
</html>'''


def generate_report(
    events: List[LogEvent],
    alerts: List[Alert],
    config: Dict[str, Any],
    output_dir: str,
    formats: List[str],
) -> Dict[str, str]:
    """Generate all requested reports. Returns dict of format -> path."""
    os.makedirs(output_dir, exist_ok=True)
    stats = compute_stats(events, alerts)
    generated: Dict[str, str] = {}

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    if 'html' in formats:
        path = os.path.join(output_dir, f'logsiem_report_{ts}.html')
        generate_html(events, alerts, stats, config, path)
        generated['html'] = path

    if 'json' in formats:
        path = os.path.join(output_dir, f'logsiem_report_{ts}.json')
        generate_json(events, alerts, stats, config, path, pretty=True)
        generated['json'] = path

    if 'csv' in formats:
        path = os.path.join(output_dir, f'logsiem_alerts_{ts}.csv')
        generate_csv(alerts, path)
        generated['csv'] = path

    if 'events_csv' in formats:
        path = os.path.join(output_dir, f'logsiem_events_{ts}.csv')
        generate_events_csv(events, path)
        generated['events_csv'] = path

    return generated
