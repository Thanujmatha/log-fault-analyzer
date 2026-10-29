import pandas as pd

def build_incidents(df):
    """Group events by fault category and service; provides a simple correlation view."""
    if df.empty:
        return pd.DataFrame(columns=["fault_category", "service", "event_count", "first_seen", "last_seen", "severity", "sample_message"])
    work = df[df["is_fault"]].copy()
    if work.empty:
        return pd.DataFrame(columns=["fault_category", "service", "event_count", "first_seen", "last_seen", "severity", "sample_message"])
    incidents = work.groupby(["fault_category", "service"], dropna=False).agg(
        event_count=("message", "size"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        severity_score=("severity_score", "max"),
        sample_message=("message", "first"),
    ).reset_index()
    incidents["severity"] = incidents["severity_score"].map(
        lambda x: "CRITICAL" if x >= 5 else "ERROR" if x >= 4 else "WARNING" if x >= 3 else "INFO"
    )
    return incidents.sort_values(["severity_score", "event_count"], ascending=[False, False]).drop(columns=["severity_score"])
