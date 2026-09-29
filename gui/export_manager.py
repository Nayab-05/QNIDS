import csv
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph,
    Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class ExportManager:

    def __init__(self, table_widget=None,
                 accuracy="94.2%", fpr="4.8%",
                 attacks=0, packets=0,
                 pie_counts=None):
        self.table_widget = table_widget
        self.accuracy     = accuracy
        self.fpr          = fpr
        self.attacks      = attacks
        self.packets      = packets
        self.pie_counts   = pie_counts or {}

    # ── Helper: read table rows ──────────────────────────
    def _get_table_rows(self, max_rows=50):
        rows = []
        if not self.table_widget:
            return rows
        limit = min(max_rows, self.table_widget.rowCount())
        for row in range(limit):
            row_data = []
            for col in range(self.table_widget.columnCount()):
                item = self.table_widget.item(row, col)
                row_data.append(item.text() if item else "")
            rows.append(row_data)
        return rows

    # ────────────────────────────────────────────────────
    # CSV EXPORT
    # ────────────────────────────────────────────────────
    def export_csv(self, filepath=None):
        try:
            if not filepath:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                filepath = os.path.join(
                    os.path.expanduser("~"), "Desktop",
                    f"QNIDS_Report_{ts}.csv"
                )

            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)

                w.writerow(["QNIDS — Quantum-Inspired Network Intrusion Detection System"])
                w.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
                w.writerow([])

                # Model performance
                w.writerow(["MODEL PERFORMANCE"])
                w.writerow(["Model", "Accuracy", "False Positive Rate", "F1-Score"])
                w.writerow(["Hybrid QPSO+RF (Ours)", self.accuracy, self.fpr, "0.996"])
                w.writerow(["Isolation Forest (Layer 2)", "—", "—", "Anomaly Detection"])
                w.writerow([])

                # Session stats
                w.writerow(["SESSION STATISTICS"])
                w.writerow(["Total Flows Analyzed", str(self.table_widget.rowCount() if self.table_widget else 0)])
                w.writerow(["Attacks Detected", str(self.attacks)])
                w.writerow(["Packets Analyzed", str(self.packets)])
                total = sum(self.pie_counts.values())
                dr = f"{(self.attacks/total*100):.1f}%" if total > 0 else "0%"
                w.writerow(["Detection Rate", dr])
                w.writerow([])

                # Attack distribution
                if self.pie_counts:
                    w.writerow(["ATTACK DISTRIBUTION"])
                    w.writerow(["Category", "Count", "Percentage"])
                    for cat, count in self.pie_counts.items():
                        if count > 0:
                            pct = f"{count/total*100:.1f}%" if total > 0 else "0%"
                            w.writerow([cat, count, pct])
                    w.writerow([])

                # Detection log
                w.writerow(["DETECTION LOG"])
                w.writerow(["Time", "Source IP", "Attack Type",
                            "Decision", "RF Conf %", "IF Score"])
                for row_data in self._get_table_rows(max_rows=200):
                    w.writerow(row_data)

            print(f"[export] CSV saved: {filepath}")
            return filepath

        except Exception as e:
            print(f"[export] CSV error: {e}")
            return None

    # ────────────────────────────────────────────────────
    # PDF EXPORT
    # ────────────────────────────────────────────────────
    def export_pdf(self, filepath=None):
        try:
            if not filepath:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                filepath = os.path.join(
                    os.path.expanduser("~"), "Desktop",
                    f"QNIDS_Report_{ts}.pdf"
                )

            doc = SimpleDocTemplate(
                filepath, pagesize=A4,
                rightMargin=0.75*inch, leftMargin=0.75*inch,
                topMargin=0.75*inch, bottomMargin=0.75*inch
            )

            story  = []
            styles = getSampleStyleSheet()

            # ── Styles
            title_style = ParagraphStyle(
                'Title', parent=styles['Title'],
                fontSize=24, textColor=colors.HexColor('#00d4ff'),
                spaceAfter=4, alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            sub_style = ParagraphStyle(
                'Sub', parent=styles['Normal'],
                fontSize=10, textColor=colors.HexColor('#64748b'),
                spaceAfter=2, alignment=TA_CENTER
            )
            section_style = ParagraphStyle(
                'Section', parent=styles['Heading2'],
                fontSize=13, textColor=colors.HexColor('#00d4ff'),
                spaceBefore=14, spaceAfter=8,
                fontName='Helvetica-Bold'
            )
            normal_style = ParagraphStyle(
                'Normal2', parent=styles['Normal'],
                fontSize=10, textColor=colors.HexColor('#334155'),
                spaceAfter=4
            )

            # ── Cover
            story.append(Paragraph("QNIDS", title_style))
            story.append(Paragraph(
                "Quantum-Inspired Network Intrusion Detection System",
                sub_style
            ))
            story.append(Paragraph(
                f"Detection Report  ·  "
                f"{datetime.now().strftime('%B %d, %Y  —  %H:%M:%S')}",
                sub_style
            ))
            story.append(Spacer(1, 0.15*inch))
            story.append(HRFlowable(
                width="100%", thickness=2,
                color=colors.HexColor('#00d4ff')
            ))
            story.append(Spacer(1, 0.1*inch))

            # ── Project Info
            story.append(Paragraph("Project Information", section_style))
            info_data = [
                ["Project",   "QNIDS — Quantum-Inspired Network Intrusion Detection System"],
                ["Dataset",   "CIC-IDS2017 (Modern Flow-Based Dataset)"],
                ["Algorithm", "QPSO Feature Selection + Random Forest + Isolation Forest"],
                ["Features",  "78 → 20 Features (QPSO Dimensionality Reduction — 74%)"],
                ["Architecture", "Dual-Layer: Layer 1 (Known Attacks) + Layer 2 (Zero-Day)"],
                ["Session",   datetime.now().strftime("%Y-%m-%d  %H:%M")],
            ]
            info_table = Table(info_data, colWidths=[1.9*inch, 4.6*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND',  (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
                ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE',    (0, 0), (-1, -1), 9),
                ('TEXTCOLOR',   (0, 0), (0, -1), colors.HexColor('#0f172a')),
                ('TEXTCOLOR',   (1, 0), (1, -1), colors.HexColor('#334155')),
                ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1),
                 [colors.white, colors.HexColor('#f8fafc')]),
                ('PADDING',     (0, 0), (-1, -1), 7),
            ]))
            story.append(info_table)

            # ── Session Statistics
            story.append(Paragraph("Session Statistics", section_style))
            total_flows = self.table_widget.rowCount() if self.table_widget else 0
            total_cat   = sum(self.pie_counts.values())
            det_rate    = f"{(self.attacks / total_cat * 100):.1f}%" if total_cat > 0 else "0%"

            stat_data = [
                ["Metric",              "Value"],
                ["Total Flows Analyzed", str(total_flows)],
                ["Attacks Detected",    str(self.attacks)],
                ["Packets Analyzed",    str(self.packets)],
                ["Detection Rate",      det_rate],
                ["Detection Mode",      "QPSO + RF (Layer 1) + Isolation Forest (Layer 2)"],
            ]
            stat_table = Table(stat_data, colWidths=[2.5*inch, 4.0*inch])
            stat_table.setStyle(TableStyle([
                ('BACKGROUND',  (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR',   (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE',    (0, 0), (-1, -1), 10),
                ('TEXTCOLOR',   (0, 1), (-1, -1), colors.HexColor('#334155')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.white, colors.HexColor('#f8fafc')]),
                ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING',     (0, 0), (-1, -1), 8),
            ]))
            story.append(stat_table)

            # ── Model Performance
            story.append(Paragraph("Model Performance", section_style))
            perf_data = [
                ["Model",                   "Accuracy", "FPR",    "F1-Score", "Status"],
                ["Hybrid QPSO+RF (Ours)",   self.accuracy, self.fpr, "0.996",  "✓ Active"],
                ["Isolation Forest (L2)",   "—",       "—",      "Anomaly",  "✓ Active"],
                ["Decision Tree (Baseline)","85.7%",   "15.1%",  "0.842",    "Reference"],
            ]
            perf_table = Table(
                perf_data,
                colWidths=[2.0*inch, 1.0*inch, 0.8*inch, 1.0*inch, 1.0*inch]
            )
            perf_table.setStyle(TableStyle([
                ('BACKGROUND',  (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR',   (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE',    (0, 0), (-1, -1), 9),
                ('BACKGROUND',  (0, 1), (-1, 2), colors.HexColor('#ecfdf5')),
                ('TEXTCOLOR',   (0, 1), (-1, 2), colors.HexColor('#065f46')),
                ('FONTNAME',    (0, 1), (-1, 1), 'Helvetica-Bold'),
                ('TEXTCOLOR',   (0, 3), (-1, -1), colors.HexColor('#64748b')),
                ('ROWBACKGROUNDS', (0, 3), (-1, -1),
                 [colors.HexColor('#f8fafc')]),
                ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('ALIGN',       (1, 0), (-1, -1), 'CENTER'),
                ('PADDING',     (0, 0), (-1, -1), 8),
            ]))
            story.append(perf_table)

            # ── Attack Distribution
            if self.pie_counts and any(v > 0 for v in self.pie_counts.values()):
                story.append(Paragraph("Attack Distribution", section_style))
                dist_data = [["Category", "Count", "Percentage", "Indicator"]]
                cat_colors = {
                    "Normal":    "#10b981",
                    "DoS":       "#ef4444",
                    "DDoS":      "#f97316",
                    "PortScan":  "#8b5cf6",
                    "BruteForce":"#3b82f6",
                    "WebAttack": "#eab308",
                    "Suspicious":"#f59e0b",
                }
                for cat, count in self.pie_counts.items():
                    if count > 0:
                        pct = f"{count / total_cat * 100:.1f}%" if total_cat > 0 else "0%"
                        bar = "█" * min(int(count / max(self.pie_counts.values()) * 20), 20)
                        dist_data.append([cat, str(count), pct, bar])

                dist_table = Table(
                    dist_data,
                    colWidths=[1.5*inch, 0.8*inch, 1.0*inch, 3.2*inch]
                )
                dist_table.setStyle(TableStyle([
                    ('BACKGROUND',  (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                    ('TEXTCOLOR',   (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                    ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE',    (0, 0), (-1, -1), 9),
                    ('TEXTCOLOR',   (0, 1), (-1, -1), colors.HexColor('#334155')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                     [colors.white, colors.HexColor('#f8fafc')]),
                    ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('ALIGN',       (1, 0), (2, -1), 'CENTER'),
                    ('PADDING',     (0, 0), (-1, -1), 7),
                ]))
                story.append(dist_table)

            # ── Detection Log
            story.append(Paragraph("Detection Log (Latest 50 Flows)", section_style))
            log_rows = self._get_table_rows(max_rows=50)

            if log_rows:
                log_data = [["Time", "Source IP", "Attack Type",
                             "Decision", "RF Conf", "IF Score"]]
                log_data.extend(log_rows)

                log_table = Table(
                    log_data,
                    colWidths=[0.75*inch, 1.0*inch, 1.8*inch,
                               1.1*inch, 0.75*inch, 0.75*inch]
                )
                log_table.setStyle(TableStyle([
                    ('BACKGROUND',  (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                    ('TEXTCOLOR',   (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                    ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE',    (0, 0), (-1, -1), 7.5),
                    ('TEXTCOLOR',   (0, 1), (-1, -1), colors.HexColor('#334155')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                     [colors.white, colors.HexColor('#f8fafc')]),
                    ('GRID',        (0, 0), (-1, -1), 0.3, colors.HexColor('#e2e8f0')),
                    ('ALIGN',       (3, 0), (-1, -1), 'CENTER'),
                    ('PADDING',     (0, 0), (-1, -1), 5),
                ]))
                story.append(log_table)
            else:
                story.append(Paragraph(
                    "No detection data available for this session.",
                    normal_style
                ))

            # ── Footer
            story.append(Spacer(1, 0.25*inch))
            story.append(HRFlowable(
                width="100%", thickness=0.5,
                color=colors.HexColor('#e2e8f0')
            ))
            story.append(Spacer(1, 0.05*inch))
            story.append(Paragraph(
                "QNIDS v1.0  ·  Final Year Project  ·  "
                "University of Azad Jammu & Kashmir  ·  BSCS 2026",
                sub_style
            ))

            doc.build(story)
            print(f"[export] PDF saved: {filepath}")
            return filepath

        except Exception as e:
            print(f"[export] PDF error: {e}")
            import traceback
            traceback.print_exc()
            return None