# Terraform Policy (OPA/Rego): Enforce Required Tags
# Converted from: sentinel/policies/enforce-required-tags.sentinel
#
# This policy ensures all AWS resources have required tags applied.

package terraform.policies.enforce_required_tags

import future.keywords.in

required_tags := ["environment", "owner", "cost_center"]

deny[msg] {
  resource := input.resource_changes[_]
  startswith(resource.type, "aws_")
  actions := resource.change.actions
  some action in actions
  action in {"create", "update"}
  tag := required_tags[_]
  tag_value := object.get(resource.change.after.tags, tag, "")
  tag_value == ""
  msg := sprintf(
    "AWS resource '%s' is missing or has an empty value for required tag '%s'.",
    [resource.address, tag],
  )
}
