"""
Parse Linux auth.log (syslog format) and Windows Security Event Log (XML).
Returns structured LogEvent objects for downstream analysis.
"""

import re
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

CURRENT_YEAR = datetime.now().year

# ── Syslog header ──────────────────────────────────────────────────────────────
SYSLOG_RE = re.compile(
    r"^(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
)

# ── SSH ────────────────────────────────────────────────────────────────────────
FAILED_PASS_RE   = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+")
ACCEPTED_RE      = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port \d+")
INVALID_USER_RE  = re.compile(r"Invalid user (\S+) from (\S+)")
MAX_AUTH_RE      = re.compile(
    r"error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)"
)

# ── sudo ───────────────────────────────────────────────────────────────────────
SUDO_CMD_RE  = re.compile(r"^(\S+)\s*:.*?USER=([^\s;]+).*?COMMAND=(.+?)$")
SUDO_FAIL_RE = re.compile(r"(\S+)\s*:\s+user NOT in sudoers")

# ── User/group management ──────────────────────────────────────────────────────
USERADD_RE  = re.compile(r"new user:\s+name=([^,\s]+)")
USERDEL_RE  = re.compile(r"delete user[:\s]+['\"]?(\S+?)['\"]?\s*$")
GROUPADD_RE = re.compile(r"new group:\s+name=(\S+)")
PASSWD_RE   = re.compile(r"password changed for (\S+)")

# ── su ─────────────────────────────────────────────────────────────────────────
SU_OPEN_RE = re.compile(r"session opened for user (\S+) by (\w+)")
SU_FAIL_RE = re.compile(r"FAILED su for (\S+) by (\S+)")


class EventType:
    FAILED_LOGIN    = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    INVALID_USER    = "invalid_user"
    MAX_AUTH        = "max_auth_exceeded"
    SUDO_COMMAND    = "sudo_command"
    SUDO_FAILURE    = "sudo_failure"
    USER_CREATED    = "user_created"
    USER_DELETED    = "user_deleted"
    GROUP_CREATED   = "group_created"
    PASSWORD_CHANGE = "password_change"
    SESSION_OPENED  = "session_opened"
    SESSION_CLOSED  = "session_closed"
    SU_SWITCH       = "su_switch"
    SU_FAILURE      = "su_failure"
    UNKNOWN         = "unknown"


@dataclass
class LogEvent:
    timestamp:   datetime
    hostname:    str
    process:     str
    pid:         Optional[int]
    message:     str
    event_type:  str
    user:        Optional[str] = None
    source_ip:   Optional[str] = None
    target_user: Optional[str] = None
    command:     Optional[str] = None
    raw_line:    str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp":   self.timestamp.isoformat(),
            "hostname":    self.hostname,
            "process":     self.process,
            "pid":         self.pid,
            "event_type":  self.event_type,
            "user":        self.user,
            "source_ip":   self.source_ip,
            "target_user": self.target_user,
            "command":     self.command,
            "message":     self.message,
        }


class LogParser:
    def parse_file(self, path: str, since: Optional[datetime] = None) -> List[LogEvent]:
        p = Path(path)
        if p.suffix.lower() == ".xml":
            return self._parse_windows_xml(p, since)
        return self._parse_syslog(p, since)

    # ── Linux syslog ───────────────────────────────────────────────────────────

    def _parse_syslog(self, path: Path, since: Optional[datetime] = None) -> List[LogEvent]:
        events: List[LogEvent] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                if not line:
                    continue
                event = self.parse_line(line)
                if event:
                    if since and event.timestamp < since:
                        continue
                    events.append(event)
        return events

    def parse_line(self, line: str) -> Optional[LogEvent]:
        m = SYSLOG_RE.match(line)
        if not m:
            return None
        ts_str, hostname, process, pid_str, message = m.groups()
        try:
            ts = datetime.strptime(f"{CURRENT_YEAR} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

        event = LogEvent(
            timestamp=ts,
            hostname=hostname,
            process=process,
            pid=int(pid_str) if pid_str else None,
            message=message,
            event_type=EventType.UNKNOWN,
            raw_line=line,
        )
        self._classify(event, message)
        return event

    def _classify(self, event: LogEvent, msg: str) -> None:
        m = FAILED_PASS_RE.search(msg)
        if m:
            event.event_type = EventType.FAILED_LOGIN
            event.user, event.source_ip = m.group(1), m.group(2)
            return

        m = ACCEPTED_RE.search(msg)
        if m:
            event.event_type = EventType.SUCCESSFUL_LOGIN
            event.user, event.source_ip = m.group(1), m.group(2)
            return

        m = INVALID_USER_RE.search(msg)
        if m:
            event.event_type = EventType.INVALID_USER
            event.user, event.source_ip = m.group(1), m.group(2)
            return

        m = MAX_AUTH_RE.search(msg)
        if m:
            event.event_type = EventType.MAX_AUTH
            event.user, event.source_ip = m.group(1), m.group(2)
            return

        # Check sudo failure before sudo command — failure lines also match SUDO_CMD_RE
        m = SUDO_FAIL_RE.search(msg)
        if m:
            event.event_type = EventType.SUDO_FAILURE
            event.user = m.group(1)
            return

        m = SUDO_CMD_RE.search(msg)
        if m and "sudo" in event.process.lower():
            event.event_type  = EventType.SUDO_COMMAND
            event.user        = m.group(1)
            event.target_user = m.group(2)
            event.command     = m.group(3).strip()
            return

        m = USERADD_RE.search(msg)
        if m:
            event.event_type = EventType.USER_CREATED
            event.user = m.group(1)
            return

        m = USERDEL_RE.search(msg)
        if m:
            event.event_type = EventType.USER_DELETED
            event.user = m.group(1)
            return

        m = GROUPADD_RE.search(msg)
        if m:
            event.event_type = EventType.GROUP_CREATED
            event.user = m.group(1)
            return

        m = PASSWD_RE.search(msg)
        if m:
            event.event_type = EventType.PASSWORD_CHANGE
            event.user = m.group(1)
            return

        m = SU_FAIL_RE.search(msg)
        if m:
            event.event_type  = EventType.SU_FAILURE
            event.target_user = m.group(1)
            event.user        = m.group(2)
            return

        # session opened — use su process as signal for privilege switch
        m = SU_OPEN_RE.search(msg)
        if m:
            if "su" in event.process.lower():
                event.event_type  = EventType.SU_SWITCH
                event.target_user = m.group(1)
                event.user        = m.group(2)
            else:
                event.event_type = EventType.SESSION_OPENED
            return

        if "session closed" in msg:
            event.event_type = EventType.SESSION_CLOSED

    # ── Windows XML ────────────────────────────────────────────────────────────

    _WIN_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    # Maps Windows Security Event IDs to (event_type, user_field, ip_field)
    _WIN_ID_MAP = {
        "4625": (EventType.FAILED_LOGIN,     "TargetUserName", "IpAddress"),
        "4624": (EventType.SUCCESSFUL_LOGIN,  "TargetUserName", "IpAddress"),
        "4720": (EventType.USER_CREATED,      "TargetUserName", None),
        "4726": (EventType.USER_DELETED,      "TargetUserName", None),
        "4648": (EventType.SU_SWITCH,         "TargetUserName", "IpAddress"),
        "4732": (EventType.SUDO_COMMAND,      "MemberName",     None),
    }

    def _parse_windows_xml(self, path: Path, since: Optional[datetime] = None) -> List[LogEvent]:
        events: List[LogEvent] = []
        try:
            root = ET.parse(path).getroot()
            for elem in root.findall(".//e:Event", self._WIN_NS):
                ev = self._parse_win_event(elem)
                if ev:
                    if since and ev.timestamp < since:
                        continue
                    events.append(ev)
        except ET.ParseError:
            pass
        return events

    def _parse_win_event(self, elem) -> Optional[LogEvent]:
        ns = self._WIN_NS
        try:
            sys_el  = elem.find("e:System", ns)
            data_el = elem.find("e:EventData", ns)

            ts_str = sys_el.find("e:TimeCreated", ns).get("SystemTime", "")
            # Python ≤3.10 fromisoformat only handles up to 6 fractional digits;
            # Windows XML uses nanoseconds (9 digits) — truncate to microseconds.
            ts_str = re.sub(r"(\.\d{6})\d+", r"\1", ts_str.replace("Z", "+00:00"))
            ts = datetime.fromisoformat(ts_str).replace(tzinfo=None)
            computer = sys_el.find("e:Computer", ns).text or ""
            eid      = sys_el.find("e:EventID", ns).text or ""

            data: dict = {}
            if data_el is not None:
                for d in data_el.findall("e:Data", ns):
                    data[d.get("Name", "")] = d.text or ""

            etype, user_key, ip_key = self._WIN_ID_MAP.get(eid, (EventType.UNKNOWN, None, None))
            return LogEvent(
                timestamp=ts,
                hostname=computer,
                process=f"EventID:{eid}",
                pid=None,
                message=str(data),
                event_type=etype,
                user=data.get(user_key) if user_key else None,
                source_ip=data.get(ip_key) if ip_key else None,
                raw_line="",
            )
        except (AttributeError, ValueError):
            return None

    # ── SQLite persistence ─────────────────────────────────────────────────────

    def save_to_db(self, events: List[LogEvent], db_path: str) -> None:
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                hostname    TEXT,
                process     TEXT,
                pid         INTEGER,
                event_type  TEXT,
                user        TEXT,
                source_ip   TEXT,
                target_user TEXT,
                command     TEXT,
                message     TEXT,
                raw_line    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ts   ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ip   ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_type ON events(event_type);
        """)
        conn.executemany(
            """INSERT INTO events
               (timestamp, hostname, process, pid, event_type, user, source_ip,
                target_user, command, message, raw_line)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    e.timestamp.isoformat(), e.hostname, e.process, e.pid,
                    e.event_type, e.user, e.source_ip, e.target_user,
                    e.command, e.message, e.raw_line,
                )
                for e in events
            ],
        )
        conn.commit()
        conn.close()
