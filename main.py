"""
Log Analyzer / Mini SIEM
Parse auth logs, detect anomalies, report suspicious activity.

Usage:
  python main.py --log /var/log/auth.log
  python main.py --log auth.log --export report.json
  python main.py --log auth.log --watch
  python main.py --log auth.log --rules custom_rules.yaml --db events.db
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

from parser import LogParser
from detector import AnomalyDetector
from reporter import Reporter

console = Console()


def _load_rules(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _alert_key(alert) -> str:
    ts = alert.timestamp.strftime("%Y-%m-%d %H:%M") if alert.timestamp else ""
    return f"{alert.alert_type}:{alert.metadata.get('source_ip', '')}:{ts}"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Log Analyzer / Mini SIEM — detect suspicious activity in auth logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --log /var/log/auth.log
  python main.py --log auth.log --export report.json
  python main.py --log auth.log --export report.txt
  python main.py --log auth.log --watch
  python main.py --log auth.log --rules custom_rules.yaml --db events.db
  python main.py --log auth.log --since "2026-05-26 00:00:00"
        """,
    )
    p.add_argument("--log",    required=True,  help="Path to log file (auth.log or .xml)")
    p.add_argument("--rules",  default="rules.yaml", help="Detection rules YAML (default: rules.yaml)")
    p.add_argument("--export", metavar="FILE", help="Export report to .json or .txt")
    p.add_argument("--watch",  action="store_true",  help="Live tail — stream new events as they arrive")
    p.add_argument("--db",     metavar="FILE", help="SQLite database path to persist parsed events")
    p.add_argument("--since",  metavar="DATETIME",
                   help='Only analyse events after this timestamp (format: "YYYY-MM-DD HH:MM:SS")')
    p.add_argument("--quiet",  action="store_true",  help="Suppress summary; show alerts only")
    return p.parse_args()


def run_analysis(
    log_path: str,
    rules: dict,
    export_path: Optional[str] = None,
    db_path: Optional[str] = None,
    since: Optional[datetime] = None,
    quiet: bool = False,
) -> None:
    parser   = LogParser()
    detector = AnomalyDetector(rules)
    reporter = Reporter()

    console.print(f"[cyan]Parsing:[/cyan] {log_path}")
    events = parser.parse_file(log_path, since=since)
    console.print(f"[green]Parsed {len(events):,} events[/green]")

    if db_path:
        parser.save_to_db(events, db_path)
        console.print(f"[green]Saved to DB:[/green] {db_path}")

    alerts = detector.analyze(events)

    if not quiet:
        reporter.print_summary(events, alerts)

    reporter.print_alerts(alerts)

    if export_path:
        reporter.export(events, alerts, export_path)
        console.print(f"[green]Report exported:[/green] {export_path}")


def watch_mode(log_path: str, rules: dict) -> None:
    parser_obj = LogParser()
    detector   = AnomalyDetector(rules)
    reporter   = Reporter()

    console.print(f"[cyan]Watching:[/cyan] {log_path}")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")

    # Baseline — parse what already exists
    all_events = parser_obj.parse_file(log_path)
    alerts     = detector.analyze(all_events)
    reporter.print_summary(all_events, alerts)
    reporter.print_alerts(alerts)

    seen_keys = {_alert_key(a) for a in alerts}

    with open(log_path, encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # jump to EOF
        while True:
            line = fh.readline()
            if line:
                event = parser_obj.parse_line(line.rstrip())
                if event:
                    all_events.append(event)
                    # Re-analyse a rolling tail for performance
                    recent     = all_events[-2000:]
                    new_alerts = detector.analyze(recent)
                    fresh      = [a for a in new_alerts if _alert_key(a) not in seen_keys]
                    if fresh:
                        reporter.print_alerts(fresh)
                        seen_keys.update(_alert_key(a) for a in fresh)
            else:
                time.sleep(0.5)


def main() -> None:
    args = _parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        console.print(f"[red]Error:[/red] log file not found: {args.log}")
        sys.exit(1)

    rules_path = Path(args.rules)
    if not rules_path.exists():
        console.print(f"[red]Error:[/red] rules file not found: {args.rules}")
        sys.exit(1)

    rules = _load_rules(str(rules_path))

    since: Optional[datetime] = None
    if args.since:
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            console.print('[red]Error:[/red] --since must be "YYYY-MM-DD HH:MM:SS"')
            sys.exit(1)

    if args.watch:
        try:
            watch_mode(str(log_path), rules)
        except KeyboardInterrupt:
            console.print("\n[yellow]Watch mode stopped.[/yellow]")
    else:
        run_analysis(
            str(log_path),
            rules,
            export_path=args.export,
            db_path=args.db,
            since=since,
            quiet=args.quiet,
        )


if __name__ == "__main__":
    main()
