<h1 align="center">Driftwatch</h1>

<p align="center">
  <img src="https://res.cloudinary.com/dcu6gtw2y/image/upload/v1776836809/Blog%20Pictures/logo-primary_aoypls.svg" width="120" alt="Driftwatch">
</p>

Catch infrastructure drift between your live AWS environment and your Terraform code.

Before you run `terraform apply`, do you know what's already in your AWS account? After previous applies, has anything changed outside of Terraform -- manually, by another tool, or by another team member?

Driftwatch answers both questions.

---

## What it does

**Pre-deploy check** -- generate a Terraform plan, hand it to Driftwatch, and it compares that plan against your live AWS environment. Flags conflicts before they become incidents: resource IDs that already exist, subnets running out of IP space, security groups that are missing, and more.

**Drift detection** -- point Driftwatch at your `terraform.tfstate` file and it compares what Terraform thinks exists against what actually exists in AWS. Surfaces resources modified outside of Terraform, deleted without Terraform knowing, or existing in AWS but not tracked by Terraform.

**Infrastructure scan** -- even without any Terraform files, Driftwatch gives you a full snapshot of your live AWS environment, exported to JSON, Excel, and Mermaid diagrams.

### Supported resources

| Category | Resources |
|----------|-----------|
| Compute | EC2 instances, Elastic IPs |
| Networking | VPCs, Subnets, Security Groups, Route Tables, Internet Gateways |
| Storage | S3 buckets |
| Database | RDS instances, DynamoDB tables |

### Output formats

- **Terminal tables** -- color-coded summary printed to stdout
- **JSON** -- full scan data for piping into other tools
- **Excel** -- formatted workbook with summary sheet and per-resource tabs
- **Mermaid diagrams** -- VPC topology, security group relationships, and routing diagrams

---

## Requirements

- Python 3.7+
- `boto3` -- AWS SDK
- `openpyxl` (optional) -- Excel export

```bash
pip install boto3 openpyxl
```

AWS credentials must be configured (`aws configure`, environment variables, or IAM role).

---

## Usage

### Scan your AWS environment

```bash
python aws_infra_scan.py --output-dir ./scan_output
```

### Pre-deploy check (plan vs live AWS)

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
python aws_infra_scan.py --plan plan.json
```

### Drift detection (tfstate vs live AWS)

```bash
python aws_infra_scan.py --state terraform.tfstate
```

### Specify region or profile

```bash
python aws_infra_scan.py --region us-west-2 --profile myprofile
```

### All options

```bash
python aws_infra_scan.py --plan plan.json --state terraform.tfstate \
    --region us-west-2 --profile myprofile \
    --output-dir ./output
```

| Flag | Description |
|------|-------------|
| `--region` | AWS region (defaults to env/config) |
| `--profile` | AWS profile name |
| `--output-dir` | Directory for output files (default: current dir) |
| `--plan` | Path to `terraform show -json` output |
| `--state` | Path to `terraform.tfstate` |
| `--no-terminal` | Skip terminal table output |
| `--no-excel` | Skip Excel export |
| `--no-json` | Skip JSON export |
| `--no-mermaid` | Skip Mermaid diagram export |

---

## Who it's for

Engineers managing AWS infrastructure with Terraform who want more confidence before deploying, especially in environments where infrastructure has been touched manually, managed by multiple people, or migrated from a non-Terraform workflow.

---

## Status

Early development. EC2, networking, VPC resources, S3, RDS, and DynamoDB are supported. IAM, Lambda, and other service support is planned next.