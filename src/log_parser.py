import json
import re
from datetime import datetime
import pandas as pd

TEXT_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+"
    r"(?:(?:\[(?P<service>[^\]]+)\])\s+)?"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)

def _normalize_level(level):
    level = str(level or "INFO").upper()
    return {"WARN": "WARNING", "FATAL": "CRITICAL"}.get(level, level)

def parse_log_text(text):
    """Parse common timestamp/level/service/message logs or JSON-lines logs."""
    rows, malformed = [], []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        row = None
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                ts = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp")
                level = obj.get("level") or obj.get("severity") or "INFO"
                message = obj.get("message") or obj.get("msg") or str(obj)
                service = obj.get("service") or obj.get("application") or "unknown"
                request_id = obj.get("request_id") or obj.get("requestId") or ""
                row = {"timestamp": ts, "level": level, "service": service,
                       "message": message, "request_id": request_id,
                       "line_no": line_no, "raw": raw}
            except (json.JSONDecodeError, TypeError):
                row = None
        if row is None:
            match = TEXT_PATTERN.match(line)
            if match:
                d = match.groupdict()
                row = {"timestamp": d["timestamp"], "level": d["level"],
                       "service": d.get("service") or "unknown",
                       "message": d["message"], "request_id": "",
                       "line_no": line_no, "raw": raw}
        if row is None:
            malformed.append({"line_no": line_no, "raw": raw})
            continue
        try:
            row["timestamp"] = pd.to_datetime(row["timestamp"], errors="coerce")
        except (ValueError, TypeError):
            row["timestamp"] = pd.NaT
        row["level"] = _normalize_level(row["level"])
        row["service"] = str(row["service"] or "unknown")
        row["message"] = str(row["message"] or "")
        row["request_id"] = str(row.get("request_id") or "")
        rows.append(row)
    columns = ["timestamp", "level", "service", "message", "request_id", "line_no", "raw"]
    df = pd.DataFrame(rows, columns=columns)
    if not df.empty:
        df["severity_score"] = df["level"].map({
            "TRACE": 0, "DEBUG": 1, "INFO": 2, "WARNING": 3,
            "ERROR": 4, "CRITICAL": 5
        }).fillna(2).astype(int)
    else:
        df["severity_score"] = pd.Series(dtype=int)
    return df, pd.DataFrame(malformed, columns=["line_no", "raw"])
