from src.log_parser import parse_log_text

def test_parse_text_log():
    text = "2026-10-29 10:00:00 ERROR [api] HTTP 500 request failed"
    df, malformed = parse_log_text(text)
    assert len(df) == 1
    assert df.iloc[0]["level"] == "ERROR"
    assert df.iloc[0]["service"] == "api"
    assert len(malformed) == 0

def test_malformed_line_is_reported():
    df, malformed = parse_log_text("this is not a supported log line")
    assert len(df) == 0
    assert len(malformed) == 1
