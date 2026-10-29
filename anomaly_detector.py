import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_anomalies(df, contamination=0.12):
    """Flag unusual time-bucket behavior using event count and severity features."""
    out = df.copy()
    out["is_anomaly"] = False
    if out.empty or out["timestamp"].isna().all() or len(out) < 12:
        return out, "Not enough timestamped events (at least 12) for a meaningful anomaly scan."
    work = out.dropna(subset=["timestamp"]).copy()
    if len(work) < 12:
        return out, "Not enough timestamped events (at least 12) for a meaningful anomaly scan."
    work["bucket"] = work["timestamp"].dt.floor("1min")
    features = work.groupby("bucket").agg(
        event_count=("message", "size"),
        error_count=("severity_score", lambda s: int((s >= 4).sum())),
        warning_count=("severity_score", lambda s: int((s == 3).sum())),
        avg_severity=("severity_score", "mean"),
    ).reset_index()
    if len(features) < 5 or features[["event_count", "error_count", "warning_count", "avg_severity"]].nunique().max() <= 1:
        return out, "Activity was too uniform to identify meaningful anomalies."
    model = IsolationForest(n_estimators=100, contamination=min(max(contamination, 0.05), 0.25),
                            random_state=42)
    features["prediction"] = model.fit_predict(features[["event_count", "error_count", "warning_count", "avg_severity"]])
    anomaly_buckets = set(features.loc[features["prediction"] == -1, "bucket"])
    mask = out["timestamp"].notna() & out["timestamp"].dt.floor("1min").isin(anomaly_buckets)
    out.loc[mask, "is_anomaly"] = True
    return out, f"Scanned {len(features)} one-minute buckets using Isolation Forest; flagged {len(anomaly_buckets)} unusual bucket(s)."
