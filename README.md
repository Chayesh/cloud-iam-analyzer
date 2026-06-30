# Cloud IAM Privilege Escalation Analyzer

A Python-based Cloud Security tool that analyzes AWS IAM permissions to identify potential privilege escalation paths, visualize attack chains, and scan Infrastructure-as-Code (Terraform) for IAM security issues.

---

## Overview

Cloud environments rely heavily on Identity and Access Management (IAM) to control access to resources. Misconfigured IAM permissions can unintentionally allow attackers to escalate privileges and gain administrative access.

This project automates the discovery of privilege escalation paths by collecting IAM policies, analyzing permissions, applying rule-based detection techniques, and generating attack visualizations.

---

## Features

* Enumerates AWS IAM users and attached policies using Boto3
* Parses IAM policy documents to extract effective permissions
* Detects multiple AWS IAM privilege escalation techniques
* Plugin-based detection rule engine for easy extensibility
* Generates IAM attack graphs
* Calculates risk scores for detected findings
* Provides remediation recommendations
* Scans Terraform IAM policies for security issues
* Structured logging and modular service architecture

---

## Current Detection Rules

* CreateRole → AttachRolePolicy → AssumeRole
* PassRole + EC2 RunInstances
* Lambda CreateFunction + PassRole
* IAM Policy Version Overwrite
* AttachUserPolicy Privilege Escalation

---

## Architecture

```text
                 Cloud IAM Privilege Escalation Analyzer

                        +----------------------+
                        |   iam_analyzer.py    |
                        +----------+-----------+
                                   |
                                   v
                        +----------------------+
                        |    Scan Service      |
                        +----------+-----------+
                                   |
              +--------------------+--------------------+
              |                                         |
              v                                         v
      +------------------+                   +------------------+
      | AWS Collector    |                   | Terraform Scanner|
      +------------------+                   +------------------+
              |
              v
      +------------------+
      | Policy Parser    |
      +------------------+
              |
              v
      +------------------+
      | Rule Engine      |
      +------------------+
              |
      +-------+-------+-------+-------+-------+
      |               |               |       |
      v               v               v       v
 CreateRole     PassRole EC2      Lambda   Policy Rules
              (Plugin Based Detection)
              |
              v
      +------------------+
      | Findings         |
      +------------------+
              |
      +-------+-------+
      |               |
      v               v
 Attack Graph     Console Output
```

---

## Project Structure

```text
app/
├── core/
├── models/
└── services/

collector/
parser/
detection/
graph/
iac_scanner/
visualization/

iam_analyzer.py
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Chayesh/cloud-iam-analyzer
cd cloud-iam-analyzer
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure AWS credentials:

```bash
aws configure
```

---

## Usage

Run an IAM scan:

```bash
python iam_analyzer.py --scan
```

Generate the IAM attack graph:

```bash
python iam_analyzer.py --graph
```

Scan Terraform IAM policies:

```bash
python iam_analyzer.py --iac terraform_test/
```

---

## Example Output

```text
User: iam-analyzer

Rule ID : AWS-IAM-001
Title   : Create Role Privilege Escalation
Severity: CRITICAL
Score   : 9.5

Attack Chain

iam:CreateRole
      ↓
iam:AttachRolePolicy
      ↓
sts:AssumeRole
      ↓
AdministratorAccess
```

---

## Technology Stack

* Python
* Boto3
* AWS IAM
* NetworkX
* Matplotlib
* Terraform
* JSON
* Logging

---

## Planned Improvements

* FastAPI REST API
* HTML / PDF / CSV reporting
* Docker support
* Unit testing with pytest
* GitHub Actions CI
* Interactive web dashboard
* Multi-account AWS scanning
* AWS Organizations support

---

## License

This project is released under the MIT License.
