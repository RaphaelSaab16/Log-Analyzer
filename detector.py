"""
Anomaly detection rules for log events.
Each detector returns a list of Alert objects; call analyze() to run all rules.
"""

from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set

from parser import LogEvent, EventType


@dataclass
class Alert:
    level:      str          # CRITICAL | HIGH | MEDIUM | LOW
    alert_type: str
    description: str
    events:     List[LogEvent] = field(default_factory=list)
    timestamp:  Optional[datetime] = None
    metadata:   dict = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = self.events[-1].timestamp if self.events else datetime.now()

    @property
    def key(self) -> str:
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M") if self.timestamp else ""
        ip = self.metadata.get("source_ip", "")
        return f"{self.alert_type}:{ip}:{ts}"

    def to_dict(self) -> dict:
        return {
            "level":       self.level,
            "type":        self.alert_type,
            "description": self.description,
            "timestamp":   self.timestamp.isoformat() if self.timestamp else None,
            "metadata":    self.metadata,
            "event_count": len(self.events),
        }


_LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class AnomalyDetector:
    def __init__(self, rules: dict):
        self.rules = rules

    def analyze(self, events: List[LogEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        alerts += self._brute_force(events)
        alerts += self._off_hours_logins(events)
        alerts += self._user_creation(events)
        alerts += self._privilege_escalation(events)
        alerts += self._sudo_failures(events)
        alerts += self._su_failures(events)
        alerts += self._max_auth(events)
        alerts += self._password_changes(events)
        alerts.sort(key=lambda a: (_LEVEL_ORDER.get(a.level, 9), a.timestamp or datetime.min))
        return alerts

    # ── Brute force ────────────────────────────────────────────────────────────

    def _brute_force(self, events: List[LogEvent]) -> List[Alert]:
        cfg       = self.rules.get("brute_force", {})
        threshold = cfg.get("threshold", 10)
        window    = timedelta(minutes=cfg.get("window_minutes", 5))

        by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
        for e in events:
            if e.event_type in (EventType.FAILED_LOGIN, EventType.INVALID_USER) and e.source_ip:
                by_ip[e.source_ip].append(e)

        alerts: List[Alert] = []
        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)
            alerted_windows: Set[str] = set()

            for i, start in enumerate(ip_events):
                bucket = start.timestamp.strftime("%Y-%m-%d %H:%M")
                if bucket in alerted_windows:
                    continue
                in_window = [
                    e for e in ip_events[i:]
                    if e.timestamp - start.timestamp <= window
                ]
                if len(in_window) >= threshold:
                    # Mark every minute covered by this window so overlapping
                    # sliding windows don't produce duplicate alerts.
                    cur = start.timestamp.replace(second=0, microsecond=0)
                    end = in_window[-1].timestamp.replace(second=0, microsecond=0)
                    while cur <= end:
                        alerted_windows.add(cur.strftime("%Y-%m-%d %H:%M"))
                        cur += timedelta(minutes=1)

                    users = sorted({e.user for e in in_window if e.user})
                    alerts.append(Alert(
                        level="CRITICAL",
                        alert_type="BRUTE_FORCE",
                        description=(
                            f"Brute force from {ip}: {len(in_window)} failed attempts "
                            f"in {cfg.get('window_minutes', 5)} min"
                        ),
                        events=in_window,
                        metadata={
                            "source_ip":      ip,
                            "attempt_count":  len(in_window),
                            "users_targeted": users,
                            "first_seen":     start.timestamp.isoformat(),
                            "last_seen":      in_window[-1].timestamp.isoformat(),
                        },
                    ))
        return alerts

    # ── Off-hours logins ───────────────────────────────────────────────────────

    def _off_hours_logins(self, events: List[LogEvent]) -> List[Alert]:
        cfg        = self.rules.get("off_hours", {})
        start_hour = cfg.get("start", 18)
        end_hour   = cfg.get("end", 8)

        alerts: List[Alert] = []
        for e in events:
            if e.event_type != EventType.SUCCESSFUL_LOGIN:
                continue
            h = e.timestamp.hour
            if h >= start_hour or h < end_hour:
                alerts.append(Alert(
                    level="HIGH",
                    alert_type="OFF_HOURS_LOGIN",
                    description=(
                        f"Off-hours login: {e.user or 'unknown'} from "
                        f"{e.source_ip or 'unknown'} at {e.timestamp.strftime('%H:%M:%S')}"
                    ),
                    events=[e],
                    metadata={
                        "user":           e.user,
                        "source_ip":      e.source_ip,
                        "login_hour":     h,
                        "business_hours": f"{end_hour:02d}:00–{start_hour:02d}:00",
                    },
                ))
        return alerts

    # ── User / group management ────────────────────────────────────────────────

    def _user_creation(self, events: List[LogEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_type == EventType.USER_CREATED:
                alerts.append(Alert(
                    level="HIGH",
                    alert_type="USER_CREATED",
                    description=f"New account created: '{e.user}' on {e.hostname}",
                    events=[e],
                    metadata={"user": e.user, "hostname": e.hostname},
                ))
            elif e.event_type == EventType.USER_DELETED:
                alerts.append(Alert(
                    level="MEDIUM",
                    alert_type="USER_DELETED",
                    description=f"Account deleted: '{e.user}' on {e.hostname}",
                    events=[e],
                    metadata={"user": e.user, "hostname": e.hostname},
                ))
        return alerts

    # ── Privilege escalation (sudo) ────────────────────────────────────────────

    def _privilege_escalation(self, events: List[LogEvent]) -> List[Alert]:
        flagged = [c.lower() for c in self.rules.get("flag_commands", [])]
        alerts: List[Alert] = []

        for e in events:
            if e.event_type != EventType.SUDO_COMMAND:
                continue
            cmd_lower = (e.command or "").lower()

            # Default: root escalation is HIGH; non-root is MEDIUM
            if e.target_user == "root":
                level = "HIGH"
                desc  = f"Sudo as root: {e.user} ran '{e.command}' on {e.hostname}"
            else:
                level = "MEDIUM"
                desc  = f"Sudo: {e.user} ran '{e.command}' as {e.target_user} on {e.hostname}"

            # Upgrade to CRITICAL for flagged dangerous commands
            for flag in flagged:
                if flag in cmd_lower:
                    level = "CRITICAL"
                    desc  = (
                        f"Dangerous sudo: {e.user} ran '{e.command}' "
                        f"as {e.target_user} on {e.hostname}"
                    )
                    break

            alerts.append(Alert(
                level=level,
                alert_type="PRIVILEGE_ESCALATION",
                description=desc,
                events=[e],
                metadata={
                    "user":        e.user,
                    "target_user": e.target_user,
                    "command":     e.command,
                    "hostname":    e.hostname,
                },
            ))
        return alerts

    # ── Sudo failures ──────────────────────────────────────────────────────────

    def _sudo_failures(self, events: List[LogEvent]) -> List[Alert]:
        by_user: Dict[str, List[LogEvent]] = defaultdict(list)
        for e in events:
            if e.event_type == EventType.SUDO_FAILURE:
                by_user[e.user or "unknown"].append(e)

        alerts: List[Alert] = []
        for user, ues in by_user.items():
            level = "HIGH" if len(ues) >= 3 else "MEDIUM"
            alerts.append(Alert(
                level=level,
                alert_type="SUDO_FAILURE",
                description=(
                    f"Unauthorised sudo by '{user}' "
                    f"({len(ues)} attempt{'s' if len(ues) > 1 else ''}) on {ues[0].hostname}"
                ),
                events=ues,
                metadata={"user": user, "attempt_count": len(ues)},
            ))
        return alerts

    # ── su failures ───────────────────────────────────────────────────────────

    def _su_failures(self, events: List[LogEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_type == EventType.SU_FAILURE:
                alerts.append(Alert(
                    level="MEDIUM",
                    alert_type="SU_FAILURE",
                    description=(
                        f"Failed su: '{e.user}' attempted to become "
                        f"'{e.target_user}' on {e.hostname}"
                    ),
                    events=[e],
                    metadata={"user": e.user, "target_user": e.target_user},
                ))
        return alerts

    # ── Max auth exceeded ──────────────────────────────────────────────────────

    def _max_auth(self, events: List[LogEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_type == EventType.MAX_AUTH:
                alerts.append(Alert(
                    level="HIGH",
                    alert_type="MAX_AUTH_EXCEEDED",
                    description=(
                        f"Max auth attempts exceeded for '{e.user}' from {e.source_ip}"
                    ),
                    events=[e],
                    metadata={"user": e.user, "source_ip": e.source_ip},
                ))
        return alerts

    # ── Password changes ───────────────────────────────────────────────────────

    def _password_changes(self, events: List[LogEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_type == EventType.PASSWORD_CHANGE:
                alerts.append(Alert(
                    level="LOW",
                    alert_type="PASSWORD_CHANGE",
                    description=f"Password changed for '{e.user}' on {e.hostname}",
                    events=[e],
                    metadata={"user": e.user, "hostname": e.hostname},
                ))
        return alerts
