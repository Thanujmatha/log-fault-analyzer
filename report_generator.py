from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def make_pdf_report(summary, incidents, hypotheses):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [Paragraph("Intelligent Log Fault Analyzer — Incident Report", styles["Title"]), Spacer(1, 12)]
    for line in summary:
        story.append(Paragraph(line, styles["BodyText"]))
        story.append(Spacer(1, 5))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Detected Incident Groups", styles["Heading2"]))
    data = [["Category", "Service", "Events", "Severity"]]
    for _, r in incidents.head(20).iterrows():
        data.append([str(r["fault_category"])[:35], str(r["service"])[:22], str(r["event_count"]), str(r["severity"])])
    if len(data) == 1:
        data.append(["No incident groups", "-", "0", "-"])
    table = Table(data, repeatRows=1, colWidths=[185, 100, 45, 90])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#263445")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("PADDING", (0,0), (-1,-1), 5),
    ]))
    story.extend([table, Spacer(1, 12), Paragraph("Root-Cause Hypotheses (not confirmed causes)", styles["Heading2"])])
    for h in hypotheses:
        story.append(Paragraph(f"<b>{h['hypothesis']}</b> ({h['confidence']} confidence)", styles["BodyText"]))
        story.append(Paragraph(f"Evidence: {h['evidence']}", styles["BodyText"]))
        story.append(Paragraph(f"Next step: {h['next_step']}", styles["BodyText"]))
        story.append(Spacer(1, 8))
    doc.build(story)
    return buffer.getvalue()
