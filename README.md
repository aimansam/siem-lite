# Siem Lite

```text
 _____ _____ ________  ___       _     _____ _____ _____ 
/  ___|_   _|  ___|  \/  |      | |   |_   _|_   _|  ___|
\ `--.  | | | |__ | .  . |______| |     | |   | | | |__  
 `--. \ | | |  __|| |\/| |______| |     | |   | | |  __| 
/\__/ /_| |_| |___| |  | |      | |_____| |_  | | | |___ 
\____/ \___/\____/\_|  |_/      \_____/\___/  \_/ \____/ 
                                                         
                                                         
```

SIEM-lite: Log analysis and security incident detection toolkit in Python. Parses log files, detects anomalies, and generates security alerts.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


## Features

- **Log Parsing** — Parse Apache, syslog, auth.log, and custom log formats
- **Anomaly Detection** — Detect suspicious patterns (failed logins, privilege escalation, unusual access times)
- **Alert Generation** — Configurable alert thresholds and severity levels
- **Report Generation** — Export findings to JSON, CSV, or text formats
- **Modular Architecture** — Pluggable parsers and detectors
- **CLI Interface** — Easy-to-use command-line interface

## Installation

```bash
pip install siem-lite
# or clone and install:
git clone https://github.com/aimansam/siem-lite
cd siem-lite
pip install -e .
```

## Quick Start

Analyze a log file:

```bash
siem-lite analyze /var/log/auth.log
```

Analyze with custom rules:

```bash
siem-lite analyze /var/log/apache/access.log --rules my_rules.yaml
```

Generate a summary report:

```bash
siem-lite report --output security_report.json
```

## Modules

| Module | Description |
|--------|-------------|
| `parser` | Log file parsing and normalization |
| `detector` | Pattern-based anomaly detection |
| `models` | Data models for events and alerts |
| `config` | Configuration and rule management |
| `report` | Report generation in multiple formats |
| `main` | CLI entry point |

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## License

MIT
