from pathlib import Path

from jinja2 import Environment
from jinja2 import FileSystemLoader


class HTMLReport:

    def generate(self, findings):

        template_dir = Path(__file__).parent / "templates"

        env = Environment(
            loader=FileSystemLoader(template_dir)
        )

        template = env.get_template(
            "report.html"
        )

        html = template.render(
            findings=findings
        )

        output = Path("reports/security_report.html")

        output.write_text(
            html,
            encoding="utf-8"
        )

        return output