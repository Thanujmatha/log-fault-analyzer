# Intelligent Log Fault Analyzer

A local demo application for parsing application logs, detecting known faults, flagging unusual log activity, correlating related events, and exporting incident summaries.

## Features
- Upload `.log`, `.txt`, or `.json` log files
- Parse common text logs and JSON-lines logs
- Classify severity and identify known error patterns
- Group recurring errors and show an incident timeline
- Optional Isolation Forest anomaly detection on log frequency/severity features
- Heuristic root-cause hypotheses with supporting evidence
- Streamlit dashboard, CSV download, and PDF incident report
- Sample logs and unit tests

## Run on Windows
1. Install Python 3.10+ from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Extract this project ZIP.
3. Open the extracted folder in VS Code, or open Command Prompt in that folder.
4. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
5. Install dependencies:
   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
6. Start the app:
   ```bat
   streamlit run app.py
   ```
7. Your browser should open the local dashboard. If it does not, visit http://localhost:8501.
8. Upload `data/sample_logs.log` or use the sample data button in the sidebar.

## Run tests
```bat
python -m pytest -q
```

## Important limitations
- Root-cause results are hypotheses based on log evidence, not proof.
- Isolation Forest is an unsupervised anomaly detector; with tiny or homogeneous datasets its results may be unreliable.
- This is a local prototype. Do not upload confidential production logs without authorization and suitable redaction.
