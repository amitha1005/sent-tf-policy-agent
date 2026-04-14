# Terraform Policy (OPA/Rego): Restrict AWS Regions
# Converted from: sentinel/policies/restrict-aws-regions.sentinel
#
# This policy ensures AWS resources are only deployed in approved regions.

package terraform.policies.restrict_aws_regions

import future.keywords.in

allowed_regions := {
  "us-east-1",
  "us-west-2",
  "eu-west-1",
}

deny[msg] {
  provider := input.configuration.provider_config[_]
  provider.name == "aws"
  region := provider.expressions.region.constant_value
  not region in allowed_regions
  msg := sprintf(
    "AWS provider is configured with region '%s' which is not allowed. Allowed regions: %v",
    [region, allowed_regions],
  )
}
