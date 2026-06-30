from pathlib import Path
from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet


class PDFReportGenerator:

    def generate(self, findings):

        output_dir = Path(__file__).parent / "output"

        output_dir.mkdir(exist_ok=True)

        pdf = output_dir / "security_report.pdf"

        styles = getSampleStyleSheet()

        doc = SimpleDocTemplate(str(pdf))

        elements = []

        elements.append(
            Paragraph(
                "<b>Cloud IAM Security Assessment</b>",
                styles["Heading1"]
            )
        )

        elements.append(
            Paragraph(
                f"Findings: {len(findings)}",
                styles["Normal"]
            )
        )

        for finding in findings:

            elements.append(
                Paragraph(
                    f"<b>{finding.metadata.title}</b>",
                    styles["Heading2"]
                )
            )

            elements.append(
                Paragraph(
                    f"Severity: {finding.metadata.severity.value}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"Score: {finding.metadata.score}",
                    styles["Normal"]
                )
            )

            chain = " → ".join(finding.chain)

            elements.append(
                Paragraph(
                    chain,
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    "<br/>",
                    styles["Normal"]
                )
            )

        doc.build(elements)

        return pdf