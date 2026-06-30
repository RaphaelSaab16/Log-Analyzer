# Log Analyzer / Mini SIEM

A Python-based log analysis tool that parses system and auth logs, detects anomalies, and flags suspicious activity — suitable as a portfolio piece for Security+, CEH, or SOC analyst roles.

## Features

| Detection Rule | Alert Level | Description |
|---|---|---|
| Brute force | CRITICAL | ≥10 failed SSH logins from one IP within 5 min |
| Off-hours login | HIGH | Successful login outside business hours (default 8am–6pm) |
| New user created | HIGH | `useradd` or Windows EventID 4720 |
| Dangerous sudo | CRITICAL | sudo with flagged commands (`/bin/bash`, `sudo su`, etc.) |
| Root escalation | HIGH | Any `sudo … USER=root` |
| Sudo failure | MEDIUM/HIGH | User not in sudoers (HIGH if ≥3 attempts) |
| su failure | MEDIUM | Failed `su` attempt |
| Max auth exceeded | HIGH | SSH max-auth threshold hit |
| Password change | LOW | `passwd` event |
| User deleted | MEDIUM | `userdel` or Windows EventID 4726 |

## Installation

```bash
cd log-analyzer
pip install -r requirements.txt
```

## Usage

```bash
# Analyse a Linux auth.log
python main.py --log /var/log/auth.log

# Use the bundled sample log
python main.py --log sample_logs/auth.log

# Parse Windows Event Log (XML export)
python main.py --log sample_logs/windows_events.xml

# Export report
python main.py --log auth.log --export report.json
python main.py --log auth.log --export report.txt

# Live tail mode — stream new events as they arrive
python main.py --log /var/log/auth.log --watch

# Only show alerts from midnight onwards
python main.py --log auth.log --since "2026-05-26 00:00:00"

# Persist events to SQLite for later querying
python main.py --log auth.log --db events.db

# Custom rules file
python main.py --log auth.log --rules custom_rules.yaml
```

## Project Structure

```
log-analyzer/
├── main.py          CLI entry point, watch mode, orchestration
├── parser.py        Syslog + Windows XML parsing → LogEvent objects
├── detector.py      Anomaly detection rules → Alert objects
├── reporter.py      Rich terminal output, JSON / TXT export
├── rules.yaml       Configurable detection thresholds
├── requirements.txt
└── sample_logs/
    ├── auth.log             Linux auth log with all detection scenarios
    └── windows_events.xml   Windows Security Event Log (XML format)
```

## Configuring Rules

Edit `rules.yaml` to tune thresholds and add flagged commands:

```yaml
brute_force:
  threshold: 10       # failed attempts to trigger alert
  window_minutes: 5   # sliding window

off_hours:
  start: 18           # 6pm — off-hours begins
  end: 8              # 8am — off-hours ends

flag_commands:        # sudo commands that trigger CRITICAL
  - sudo su
  - /bin/bash
  - passwd
```

## Architecture

```
auth.log / XML
     │
     ▼
 LogParser          parse_file() → List[LogEvent]
     │
     ▼
AnomalyDetector     analyze() → List[Alert]
     │
     ▼
  Reporter          print_summary() / print_alerts() / export()
```

- **parser.py** — pure parsing, no detection logic; supports syslog and Windows XML formats
- **detector.py** — stateless per-run; all thresholds come from `rules.yaml`
- **reporter.py** — all presentation; `rich` for terminal, stdlib for file export
- **SQLite** — optional; `--db events.db` persists events with indices on timestamp, IP, and event type

## Sample Output

```
╭─────────────────────────── LOG ANALYSIS SUMMARY ───────────────────────────╮
│ Total events       53    │  Alert Severity             │
│ Failed logins      19    │  CRITICAL   3               │
│ Successful logins   4    │  HIGH       6               │
│ Sudo commands       4    │  MEDIUM     4               │
│ Users created       1    │  LOW        1               │
│ Total alerts       14    │                             │
╰─────────────────────────────────────────────────────────────────────────────╯

[!!] CRITICAL  BRUTE_FORCE  @ 2026-05-26 02:15:31
  Brute force from 203.0.113.5: 12 failed attempts in 5 min
    source_ip:      203.0.113.5
    attempt_count:  12
    users_targeted: admin, root, ubuntu, pi
```
