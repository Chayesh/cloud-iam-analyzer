import json
import argparse

from app.core.logger import logger
from app.services.scan_service import ScanService

from visualization.graph_visualizer import draw_attack_chain
from graph.attack_graph import AttackGraphBuilder
from iac_scanner.terraform_scanner import TerraformScanner


def banner():

    print("\nCloud IAM Privilege Escalation Analyzer")
    print("=======================================\n")


# ------------------------------------------------
# Display Findings
# ------------------------------------------------
def run_detection(findings):

    logger.info("Displaying privilege escalation findings...")

    if not findings:

        logger.info("No privilege escalation paths detected.")
        return

    for finding in findings:

        metadata = finding.metadata

        logger.warning(
            f"{metadata.severity.value} privilege escalation detected for {finding.user}"
        )

        print(f"\nUser: {finding.user}\n")

        print(f"Rule ID : {metadata.rule_id}")
        print(f"Title   : {metadata.title}")
        print(f"Severity: {metadata.severity.value}")
        print(f"Score   : {metadata.score}")

        print("\nAttack Chain:")

        for step in finding.chain:
            print(" →", step)

        print("\nRecommended Fix:")

        for recommendation in metadata.recommendations:
            print(" -", recommendation)

        if metadata.references:

            print("\nReferences:")

            for ref in metadata.references:
                print(" -", ref)

        print()

        draw_attack_chain(finding.chain)


# ------------------------------------------------
# Attack Graph
# ------------------------------------------------
def build_attack_graph(permissions):

    logger.info("Generating IAM attack graph...")

    graph_builder = AttackGraphBuilder(permissions)

    graph_builder.build_graph()

    graph_builder.visualize()


# ------------------------------------------------
# Terraform Scan
# ------------------------------------------------
def scan_terraform(directory):

    logger.info("Scanning Terraform policies...")

    scanner = TerraformScanner(directory)

    findings = scanner.scan()

    if not findings:

        logger.info("No Terraform IAM issues detected.")

        return

    for finding in findings:

        print(f"\n[{finding['severity']}] {finding['issue']}\n")

        print("Attack Chain:")

        for step in finding["chain"]:
            print(" →", step)

        if "fix" in finding:

            print("\nRecommended Fix:")

            for fix in finding["fix"]:
                print(" -", fix)

        print()


# ------------------------------------------------
# CLI
# ------------------------------------------------
def main():

    parser = argparse.ArgumentParser(
        description="Cloud IAM Privilege Escalation Analyzer"
    )

    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan AWS IAM"
    )

    parser.add_argument(
        "--graph",
        action="store_true",
        help="Show IAM attack graph"
    )

    parser.add_argument(
        "--iac",
        help="Scan Terraform IAM policies"
    )

    args = parser.parse_args()

    banner()

    if args.scan:

        scan_service = ScanService()

        permissions, findings = scan_service.scan()

        run_detection(findings)

    elif args.graph:

        with open("data/permissions.json") as f:
            permissions = json.load(f)

        build_attack_graph(permissions)

    elif args.iac:

        scan_terraform(args.iac)

    else:

        parser.print_help()


if __name__ == "__main__":
    main()