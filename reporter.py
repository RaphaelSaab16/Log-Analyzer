"""
Terminal output (rich) and file export (JSON / TXT) for analysis results.
"""

import json
from collections import Counter
from datetime import datetime
from typing import List

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from parser import LogEvent, EventType
from detector import Alert

console = Console()

_LEVEL_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
}
_LEVEL_ICON = {
    "CRITICAL": "[!!]",
    "HIGH":     "[!] ",
    "MEDIUM":   "[*] ",
    "LOW":      "[i] ",
}


class Reporter:

    # ── Terminal output ────────────────────────────────────────────────────────

    def print_summary(self, events: List[LogEvent], alerts: List[Alert]) -> None:
        console.print()
        console.print(Rule("[bold cyan]  LOG ANALYSIS SUMMARY  [/bold cyan]"))
        console.print()

        if not events:
            console.print("[yellow]No events parsed from log file.[/yellow]")
            return

        timestamps   = [e.timestamp for e in events]
        time_range   = (
            f"{min(timestamps).strftime('%Y-%m-%d %H:%M:%S')}  →  "
            f"{max(timestamps).strftime('%Y-%m-%d %H:%M:%S')}"
        )
        type_counts  = Counter(e.event_type for e in events)
        alert_counts = Counter(a.level for a in alerts)

        failed_ips = Counter(
            e.source_ip
            for e in events
            if e.event_type in (EventType.FAILED_LOGIN, EventType.INVALID_USER)
            and e.source_ip
        )
        successful = [e for e in events if e.event_type == EventType.SUCCESSFUL_LOGIN]

        # ── Overview table ─────────────────────────────────────────────────────
        ov = Table(title="Overview", box=box.ROUNDED, show_header=False, min_width=42)
        ov.add_column("Metric", style="bold")
        ov.add_column("Value", justify="right")
        ov.add_row("Total events",        str(len(events)))
        ov.add_row("Time range",          time_range)
        ov.add_row("Failed logins",
                   str(type_counts.get(EventType.FAILED_LOGIN, 0)
                       + type_counts.get(EventType.INVALID_USER, 0)))
        ov.add_row("Successful logins",   str(len(successful)))
        ov.add_row("Sudo commands",       str(type_counts.get(EventType.SUDO_COMMAND, 0)))
        ov.add_row("Users created",       str(type_counts.get(EventType.USER_CREATED, 0)))
        ov.add_row("Password changes",    str(type_counts.get(EventType.PASSWORD_CHANGE, 0)))
        ov.add_row("Total alerts",        f"[bold]{len(alerts)}[/bold]")

        # ── Severity breakdown ─────────────────────────────────────────────────
        sev = Table(title="Alerts by Severity", box=box.ROUNDED, min_width=30)
        sev.add_column("Level",  style="bold")
        sev.add_column("Count",  justify="right")
        for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = alert_counts.get(lvl, 0)
            if n:
                col = _LEVEL_COLOR[lvl]
                sev.add_row(f"[{col}]{lvl}[/{col}]", f"[{col}]{n}[/{col}]")

        console.print(Columns([ov, sev]))
        console.print()

        # ── Top offending IPs ──────────────────────────────────────────────────
        if failed_ips:
            ip_tbl = Table(title="Top Offending IPs  (Failed Logins)", box=box.ROUNDED)
            ip_tbl.add_column("Rank", justify="right", style="dim")
            ip_tbl.add_column("IP Address", style="red")
            ip_tbl.add_column("Attempts",  justify="right")
            for rank, (ip, cnt) in enumerate(failed_ips.most_common(10), 1):
                ip_tbl.add_row(str(rank), ip, str(cnt))
            console.print(ip_tbl)
            console.print()

        # ── Successful logins ──────────────────────────────────────────────────
        if successful:
            sl_tbl = Table(title="Successful Logins", box=box.ROUNDED)
            sl_tbl.add_column("Timestamp")
            sl_tbl.add_column("User",      style="green")
            sl_tbl.add_column("Source IP")
            sl_tbl.add_column("Host")
            shown = successful[:20]
            for e in shown:
                sl_tbl.add_row(
                    e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    e.user or "—",
                    e.source_ip or "—",
                    e.hostname,
                )
            console.print(sl_tbl)
            if len(successful) > 20:
                console.print(f"[dim]  … {len(successful) - 20} more not shown[/dim]")
            console.print()

    def print_alerts(self, alerts: List[Alert]) -> None:
        if not alerts:
            console.print("[green]  No alerts generated.[/green]\n")
            return

        console.print(Rule("[bold red]  SECURITY ALERTS  [/bold red]"))
        console.print()

        for alert in alerts:
            color = _LEVEL_COLOR.get(alert.level, "white")
            icon  = _LEVEL_ICON.get(alert.level, "[?]")
            ts    = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "N/A"

            title = (
                f"[{color}]{icon} {alert.level:<8}[/{color}]"
                f"  {alert.alert_type}   [{ts}]"
            )

            body = Text()
            body.append(alert.description + "\n")
            if alert.metadata:
                body.append("\n  Details\n", style="dim")
                for k, v in alert.metadata.items():
                    if v is None or v == "" or v == []:
                        continue
                    if isinstance(v, list):
                        v = ", ".join(str(x) for x in v)
                    body.append(f"    {k}: ", style="dim bold")
                    body.append(f"{v}\n",     style="dim")

            console.print(Panel(body, title=title, border_style=color, padding=(0, 1)))

        console.print()

    # ── Export ─────────────────────────────────────────────────────────────────

    def export(self, events: List[LogEvent], alerts: List[Alert], path: str) -> None:
        if path.endswith(".json"):
            self._export_json(events, alerts, path)
        else:
            self._export_txt(events, alerts, path)

    def _export_json(self, events: List[LogEvent], alerts: List[Alert], path: str) -> None:
        payload = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_events":    len(events),
                "total_alerts":    len(alerts),
                "alert_breakdown": dict(Counter(a.level for a in alerts)),
            },
            "alerts": [a.to_dict() for a in alerts],
            "events": [e.to_dict() for e in events],
        }
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)

    def _export_txt(self, events: List[LogEvent], alerts: List[Alert], path: str) -> None:
        lines = [
            "=" * 72,
            "  LOG ANALYSIS REPORT",
            f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Events    : {len(events)}",
            f"  Alerts    : {len(alerts)}",
            "=" * 72,
            "",
        ]

        counts = Counter(a.level for a in alerts)
        lines += [
            "Alert Summary",
            "-" * 40,
            *[f"  {lvl:<10}: {counts.get(lvl, 0)}"
              for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")],
            "",
            "=" * 72,
            "SECURITY ALERTS",
            "=" * 72,
        ]

        for a in alerts:
            ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "N/A"
            lines.append(f"\n[{a.level}] {a.alert_type}  @ {ts}")
            lines.append(f"  {a.description}")
            for k, v in a.metadata.items():
                if v is None or v == "" or v == []:
                    continue
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v)
                lines.append(f"  {k}: {v}")

        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
