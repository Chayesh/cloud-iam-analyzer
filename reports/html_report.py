from pathlib import Path

from jinja2 import Environment
from jinja2 import FileSystemLoader


class HTMLReportGenerator:

    def generate(self, findings):

        template_dir = Path(__file__).parent / "templates"

        env = Environment(

            loader=FileSystemLoader(template_dir)

        )

        template = env.get_template("report.html")

        html = template.render(

            findings=findings

        )

        output_dir = Path(__file__).parent / "output"

        output_dir.mkdir(

            exist_ok=True

        )

        output_file = output_dir / "security_report.html"

        output_file.write_text(

            html,

            encoding="utf-8"

        )

        return output_file