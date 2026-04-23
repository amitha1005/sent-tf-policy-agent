# sent-tf-policy-agent

A test repository demonstrating the conversion of [HashiCorp Sentinel](https://developer.hashicorp.com/sentinel) policies to [Terraform Cloud OPA (Open Policy Agent)](https://developer.hashicorp.com/terraform/cloud-docs/policy-enforcement/opa) policies written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/).

## Overview

As Terraform Cloud and Terraform Enterprise support both Sentinel and OPA (Rego) as policy frameworks, organizations may wish to migrate their existing Sentinel policies to OPA. This repository provides side-by-side examples of common infrastructure governance policies in both formats.

## Repository Structure

```
.
├── sentinel/                        # Original Sentinel policies
│   ├── sentinel.hcl                 # Sentinel policy set configuration
│   └── policies/
│       ├── restrict-aws-instance-type.sentinel
│       ├── enforce-required-tags.sentinel
│       └── restrict-aws-regions.sentinel
│
└── terraform-policies/              # Converted OPA/Rego policies
    ├── policies.hcl                 # Terraform policy set configuration
    └── policies/
        ├── restrict-aws-instance-type.rego
        ├── enforce-required-tags.rego
        └── restrict-aws-regions.rego
```

## Policy Examples

### 1. Restrict AWS EC2 Instance Types

Ensures only approved EC2 instance types (`t2.micro`, `t2.small`, `t2.medium`, `t3.micro`, `t3.small`, `t3.medium`) are used.

| Format   | File |
|----------|------|
| Sentinel | [`sentinel/policies/restrict-aws-instance-type.sentinel`](sentinel/policies/restrict-aws-instance-type.sentinel) |
| OPA/Rego | [`terraform-policies/policies/restrict-aws-instance-type.rego`](terraform-policies/policies/restrict-aws-instance-type.rego) |

### 2. Enforce Required Tags

Ensures all AWS resources include the required tags: `environment`, `owner`, and `cost_center`.

| Format   | File |
|----------|------|
| Sentinel | [`sentinel/policies/enforce-required-tags.sentinel`](sentinel/policies/enforce-required-tags.sentinel) |
| OPA/Rego | [`terraform-policies/policies/enforce-required-tags.rego`](terraform-policies/policies/enforce-required-tags.rego) |

### 3. Restrict AWS Regions

Ensures AWS resources are only deployed in approved regions: `us-east-1`, `us-west-2`, and `eu-west-1`.

| Format   | File |
|----------|------|
| Sentinel | [`sentinel/policies/restrict-aws-regions.sentinel`](sentinel/policies/restrict-aws-regions.sentinel) |
| OPA/Rego | [`terraform-policies/policies/restrict-aws-regions.rego`](terraform-policies/policies/restrict-aws-regions.rego) |

## Key Differences: Sentinel vs OPA/Rego

| Aspect | Sentinel | OPA/Rego |
|--------|----------|----------|
| Language | Sentinel DSL (HCL-like) | Rego |
| Enforcement levels | `advisory`, `soft-mandatory`, `hard-mandatory` | `advisory`, `mandatory` |
| Policy result | Boolean `main` rule | `deny` set with violation messages |
| Input data | `tfplan/v2`, `tfstate/v2` imports | `input` object (JSON plan) |
| Built-in functions | Sentinel standard library | OPA built-ins |

## Resources

- [Terraform Cloud OPA Policy Enforcement](https://developer.hashicorp.com/terraform/cloud-docs/policy-enforcement/opa)
- [Sentinel Documentation](https://developer.hashicorp.com/sentinel/docs)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
