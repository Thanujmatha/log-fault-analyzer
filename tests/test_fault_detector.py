from src.log_parser import parse_log_text
from src.fault_detector import detect_faults

def test_database_timeout_detection():
    df, _ = parse_log_text("2026-10-29 10:00:00 ERROR [database] Database connection timeout")
    out = detect_faults(df)
    assert out.iloc[0]["fault_category"] == "Database timeout"
    assert bool(out.iloc[0]["is_fault"])
