# Terraform Policy (OPA/Rego): Restrict AWS EC2 Instance Types
# Converted from: sentinel/policies/restrict-aws-instance-type.sentinel
#
# This policy enforces that only approved EC2 instance types are used.

package terraform.policies.restrict_aws_instance_type

import future.keywords.in

allowed_instance_types := {
  "t2.micro",
  "t2.small",
  "t2.medium",
  "t3.micro",
  "t3.small",
  "t3.medium",
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  actions := resource.change.actions
  some action in actions
  action in {"create", "update"}
  instance_type := resource.change.after.instance_type
  not instance_type in allowed_instance_types
  msg := sprintf(
    "AWS EC2 instance '%s' uses instance type '%s' which is not allowed. Allowed types: %v",
    [resource.address, instance_type, allowed_instance_types],
  )
}
