# Driftwatch

Driftwatch is an open source tool for catching infrastructure drift between your live AWS environment and your Terraform code.

It solves a specific problem: before you run `terraform apply`, do you actually know what's already sitting in your AWS account? And after previous applies, has anything changed outside of Terraform -- manually, by another tool, or by another team member?

Driftwatch answers both questions.

---

## What it does

**Pre-deploy check** -- you generate a Terraform plan, hand it to Driftwatch, and it compares that plan against your live AWS environment. It flags conflicts before they become incidents: resource IDs that already exist, subnets running out of IP space, security groups that are missing, and more.

**Drift detection** -- you point Driftwatch at your `terraform.tfstate` file and it compares what Terraform thinks exists against what actually exists in AWS. It surfaces resources that have been modified outside of Terraform, resources that have been deleted without Terraform knowing, and resources that exist in AWS but are not tracked by Terraform at all.

**Infrastructure scan** -- even without any Terraform files, Driftwatch gives you a full snapshot of your live AWS environment: EC2 instances, Elastic IPs, VPCs, subnets, security groups, route tables, and internet gateways, exported to JSON and Excel.

---

## Who it's for

Engineers who manage AWS infrastructure with Terraform and want more confidence before deploying changes, especially in environments where infrastructure has been touched manually, managed by multiple people, or migrated from a non-Terraform workflow.

---

## Status

Early development. Currently supports EC2, networking, and core VPC resources. Database and storage resource support (RDS, S3, DynamoDB) is planned next.