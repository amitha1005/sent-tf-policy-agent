# FSBP top 10 comparison package

This folder contains two generated Terraform Policy sets for the same 10 AWS Security Hub FSBP controls:

- `internal-conversion/`: output generated from selected Sentinel source policies
- `direct-id-only/`: output generated directly from Security Hub control IDs

Each policy subfolder contains the packaged artifacts needed for review and local TF Policy testing:

- `policy.policy.hcl`
- `test.policytest.hcl`
- `main.tf`
- `report.md`
- `requirement.txt`
- `gwt.json`
