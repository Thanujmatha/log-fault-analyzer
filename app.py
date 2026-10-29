import json
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

from src.log_parser import parse_log_text
from src.fault_detector import detect_faults
from src.anomaly_detector import detect_anomalies
from src.correlation import build_incidents
from src.root_cause import generate_hypotheses
from src.report_generator import make_pdf_report

st.set_page_config(page_title="Intelligent Log Fault Analyzer", page_icon="🛠️", layout="wide")
st.title("🛠️ Intelligent Log Fault Analyzer")
st.caption("Log parsing • Fault detection • Anomaly screening • Incident correlation • Evidence-based hypotheses")

SAMPLE_PATH = Path(__file__).parent / "data" / "sample_logs.log"
SAMPLE_LOGS = SAMPLE_PATH.read_text(encoding="utf-8") if SAMPLE_PATH.exists() else ""

with st.sidebar:
    st.header("Input")
    uploaded = st.file_uploader("Upload a log file", type=["log", "txt", "json"])
    use_sample = st.button("Load built-in sample logs", use_container_width=True)
    st.divider()
    st.subheader("Analysis settings")
    run_ml = st.checkbox("Run ML anomaly screening", value=True)
    st.caption("ML needs enough timestamped events and variation to be meaningful.")
    st.caption("Privacy: files are processed by this local app; avoid sharing sensitive production logs.")

if uploaded is not None:
    raw_text = uploaded.getvalue().decode("utf-8", errors="replace")
    filename = uploaded.name
elif use_sample or "raw_text" not in st.session_state:
    raw_text = SAMPLE_LOGS
    filename = "sample_logs.log"
else:
    raw_text = st.session_state.get("raw_text", SAMPLE_LOGS)
    filename = st.session_state.get("filename", "sample_logs.log")
st.session_state["raw_text"] = raw_text
st.session_state["filename"] = filename

if not raw_text.strip():
    st.info("Upload a .log, .txt, or JSON-lines file, or click **Load built-in sample logs**.")
    st.stop()

with st.spinner("Parsing and analyzing log events..."):
    parsed, malformed = parse_log_text(raw_text)
    analyzed = detect_faults(parsed)
    ml_message = "ML anomaly screening disabled."
    if run_ml:
        analyzed, ml_message = detect_anomalies(analyzed)
    else:
        analyzed["is_anomaly"] = False
    incidents = build_incidents(analyzed)
    hypotheses = generate_hypotheses(analyzed)

if analyzed.empty:
    st.error("No supported log records were parsed. Check the expected timestamp and severity format.")
    st.code("2026-10-29 10:00:01 INFO [api] Application started")
    if not malformed.empty:
        st.write("Unparsed lines", malformed)
    st.stop()

total = len(analyzed)
errors = int(analyzed["level"].isin(["ERROR", "CRITICAL"]).sum())
warnings = int((analyzed["level"] == "WARNING").sum())
anomalies = int(analyzed["is_anomaly"].sum())
critical = int((analyzed["level"] == "CRITICAL").sum())

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Parsed events", f"{total:,}")
m2.metric("Errors", f"{errors:,}")
m3.metric("Warnings", f"{warnings:,}")
m4.metric("Critical", f"{critical:,}")
m5.metric("Anomaly-flagged events", f"{anomalies:,}")
st.caption(f"File: {filename} · {len(malformed)} malformed/unrecognized line(s) · {ml_message}")

tab_overview, tab_events, tab_incidents, tab_rca, tab_export = st.tabs(
    ["Overview", "Log Explorer", "Incident Groups", "Root-Cause Hypotheses", "Export Reports"]
)

with tab_overview:
    left, right = st.columns(2)
    with left:
        counts = analyzed["level"].value_counts().rename_axis("Level").reset_index(name="Count")
        st.plotly_chart(px.bar(counts, x="Level", y="Count", title="Events by severity",
                               color="Level"), use_container_width=True)
    with right:
        cats = analyzed[analyzed["is_fault"]]["fault_category"].value_counts().rename_axis("Fault category").reset_index(name="Count")
        if cats.empty:
            st.info("No fault patterns were detected.")
        else:
            st.plotly_chart(px.bar(cats, x="Count", y="Fault category", orientation="h",
                                   title="Detected fault categories"), use_container_width=True)
    timed = analyzed.dropna(subset=["timestamp"]).copy()
    if not timed.empty:
        timed["minute"] = timed["timestamp"].dt.floor("min")
        timeline = timed.groupby(["minute", "level"]).size().reset_index(name="Events")
        st.plotly_chart(px.line(timeline, x="minute", y="Events", color="level",
                                markers=True, title="Event timeline by severity"), use_container_width=True)
    else:
        st.warning("No valid timestamps available for the timeline chart.")

with tab_events:
    levels = sorted(analyzed["level"].dropna().unique().tolist())
    selected_levels = st.multiselect("Filter severity", levels, default=levels)
    service_options = sorted(analyzed["service"].dropna().astype(str).unique().tolist())
    selected_services = st.multiselect("Filter service", service_options, default=service_options)
    search = st.text_input("Search message text")
    view = analyzed[analyzed["level"].isin(selected_levels) & analyzed["service"].astype(str).isin(selected_services)].copy()
    if search:
        view = view[view["message"].astype(str).str.contains(search, case=False, regex=False)]
    display_cols = ["timestamp", "level", "service", "message", "fault_category", "is_anomaly", "line_no"]
    st.dataframe(view[display_cols], use_container_width=True, hide_index=True)
    st.download_button("Download filtered events CSV", view[display_cols].to_csv(index=False).encode("utf-8"),
                       file_name="filtered_log_events.csv", mime="text/csv")

with tab_incidents:
    if incidents.empty:
        st.success("No warning/error incident groups found.")
    else:
        st.dataframe(incidents, use_container_width=True, hide_index=True)
        st.caption("Groups are heuristic clusters by fault category and service, not a guarantee that events share one cause.")

with tab_rca:
    st.warning("These are explainable hypotheses based on text patterns and event timing. Validate them against metrics, traces, stack traces, and deployment history.")
    for i, h in enumerate(hypotheses, start=1):
        with st.expander(f"{i}. {h['hypothesis']} — {h['confidence']} confidence", expanded=(i == 1)):
            st.write("**Evidence:**", h["evidence"])
            st.write("**Recommended next step:**", h["next_step"])

with tab_export:
    summary = [
        f"Source file: {filename}",
        f"Parsed events: {total}",
        f"ERROR/CRITICAL events: {errors}",
        f"Warnings: {warnings}",
        f"Critical events: {critical}",
        f"Anomaly-flagged events: {anomalies}",
        f"Unparsed lines: {len(malformed)}",
        f"ML note: {ml_message}",
    ]
    report_bytes = make_pdf_report(summary, incidents, hypotheses)
    st.download_button("Download incident report PDF", report_bytes,
                       file_name="log_fault_incident_report.pdf", mime="application/pdf")
    st.download_button("Download all analyzed events CSV",
                       analyzed.to_csv(index=False).encode("utf-8"),
                       file_name="analyzed_log_events.csv", mime="text/csv")
    if not malformed.empty:
        st.subheader("Unparsed lines")
        st.dataframe(malformed, use_container_width=True, hide_index=True)

with st.expander("About this prototype"):
    st.markdown("""
    - **Rule-based detection** catches patterns explicitly defined in `src/fault_detector.py`.
    - **Anomaly detection** uses Isolation Forest on minute-level event counts and severity features.
    - **Correlation** groups similar faults by category and service.
    - **Root-cause hypotheses** explain what to inspect next; they do not prove causation.
    - For a production system, add streaming ingestion, access controls, secret redaction, trace IDs, alerting, and larger labeled evaluation datasets.
    """)
