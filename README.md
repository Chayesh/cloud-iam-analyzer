# ☁️ Cloud IAM Privilege Escalation Analyzer

> Detect AWS IAM privilege escalation paths, analyze IAM permissions, visualize attack chains, and identify security risks.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-009688)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED)
![AWS](https://img.shields.io/badge/AWS-IAM-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

A modular cloud security tool that automates AWS IAM security analysis by detecting privilege escalation paths, generating attack graphs, scanning Terraform IAM policies, and exposing REST APIs through FastAPI.


## Overview

Misconfigured AWS IAM permissions are one of the most common causes of cloud privilege escalation.

This project automates IAM security analysis by:

- Enumerating AWS IAM users and attached policies
- Parsing IAM policy documents
- Detecting privilege escalation techniques
- Generating attack graphs
- Calculating identity risk scores
- Recommending remediation steps
- Scanning Terraform IAM configurations

The project follows a modular architecture that separates data collection, policy parsing, detection logic, reporting, and API services.

## Features

### AWS IAM Analysis

- Enumerate IAM Users
- Enumerate Attached Policies
- Parse IAM Policy Documents
- Extract Effective Permissions

### Privilege Escalation Detection

- CreateRole → AttachRolePolicy → AssumeRole
- PassRole + EC2 Launch
- Lambda + PassRole
- Policy Version Overwrite
- AttachUserPolicy Escalation

### Visualization

- Attack Graph Generation
- Privilege Escalation Chains

### Infrastructure as Code

- Terraform IAM Scanner

### REST API

- FastAPI
- Swagger UI
- JSON Responses

### Engineering

- Docker Support
- GitHub Actions CI
- Unit Tests
- Structured Logging

                +----------------------+
                |     FastAPI API      |
                +----------+-----------+
                           |
                           |
                    ScanService
                           |
      +--------------------+--------------------+
      |                                         |
 AWSCollector                          TerraformScanner
      |                                         |
      +--------------------+--------------------+
                           |
                    Policy Parser
                           |
                           |
                 Escalation Detector
                           |
       +---------+---------+---------+
       |         |         |         |
 CreateRole  PassRole   Lambda   Policy Rules
                           |
                      Risk Engine
                           |
                    Recommendations
                           |
             +-------------+-------------+
             |                           |
       CLI Output               Attack Graph


## Detection Rules

| Rule | Severity |
|------|----------|
| CreateRole + AttachRolePolicy + AssumeRole | Critical |
| PassRole + EC2 RunInstances | Critical |
| Lambda + PassRole | High |
| Policy Version Overwrite | High |
| AttachUserPolicy | Critical |

## Technology Stack

| Category | Technology |
|----------|------------|
| Language | Python |
| Cloud SDK | Boto3 |
| API | FastAPI |
| Visualization | NetworkX |
| IaC | Terraform |
| Testing | pytest |
| CI | GitHub Actions |
| Containerization | Docker |

## Installation

```bash
git clone https://github.com/Chayesh/cloud-iam-analyzer.git

cd cloud-iam-analyzer

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```
## Run

### CLI

```bash
python iam_analyzer.py --scan
```

Generate Attack Graph

```bash
python iam_analyzer.py --graph
```

Scan Terraform

```bash
python iam_analyzer.py --iac terraform_test/
```

## REST API

Start the API

```bash
uvicorn api.app:app --reload
```

Swagger UI

```
http://127.0.0.1:8000/docs
```

Available Endpoints

| Method | Endpoint | Description |
|---------|----------|-------------|
| GET | / | API Status |
| GET | /health | Health Check |
| POST | /scan | Run IAM Scan |

## Docker

```bash
docker compose build

docker compose up
```

Swagger

```
http://localhost:8000/docs
```

collector/
parser/
detection/
graph/
visualization/
api/
tests/
app/

User: iam-analyzer

Severity: CRITICAL

Attack Chain

CreateRole
↓

AttachRolePolicy
↓

AssumeRole
↓

AdministratorAccess

## Roadmap

- [x] IAM Enumeration
- [x] Privilege Escalation Detection
- [x] Attack Graph
- [x] Terraform Scanner
- [x] FastAPI
- [x] Docker
- [x] Unit Tests
- [x] GitHub Actions
- [ ] HTML Report
- [ ] PDF Report
- [ ] CSV Export

## Future Improvements

- Multi-account AWS Support
- AWS Organizations Support
- IAM Relationship Graph
- Least Privilege Recommendations
- Historical Scan Comparison
- Policy Diffing

## License

Released under the MIT License.