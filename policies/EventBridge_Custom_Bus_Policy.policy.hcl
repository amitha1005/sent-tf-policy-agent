# LIMITATION: This policy matches resources by attribute values in planned state, but cannot verify 
# configuration-level references. Resources with unresolved references may not match reliably.
# The policy uses core::getresources() to find matching event bus policies, which works by comparing
# resolved attribute values rather than checking configuration-level reference metadata.

# EventBridge Custom Event Bus Should Have Attached Policy
#
# This policy enforces that all custom EventBridge event buses have an attached resource policy.
# It validates that each aws_cloudwatch_event_bus resource has a corresponding 
# aws_cloudwatch_event_bus_policy resource with matching event_bus_name.
#
# Resources checked:
# - aws_cloudwatch_event_bus
# - aws_cloudwatch_event_bus_policy (for cross-resource validation)
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/eventbridge-controls.html#eventbridge-3

policy {}

# Cache all event bus policies once for performance
locals {
  # Get all event bus policy resources
  all_bus_policies = core::getresources("aws_cloudwatch_event_bus_policy", {})
  
  # Extract event_bus_name values from policies that have this attribute set
  # Note: Resources from getresources() use direct attribute access (policy.event_bus_name)
  bus_names_with_policies = [
    for policy in local.all_bus_policies :
    policy.event_bus_name
    if core::try(policy.event_bus_name, null) != null
  ]
}

resource_policy "aws_cloudwatch_event_bus" "has_attached_policy" {

  enforcement_level = "advisory"
  locals {
    # Get the name of this event bus
    bus_name = core::try(attrs.name, null)
    
    # Check if this bus name exists in the list of buses with policies
    has_policy = local.bus_name != null && core::contains(local.bus_names_with_policies, local.bus_name)
  }
  
  enforce {
    condition = local.has_policy
 error_message = "Policy should be attached for 'aws_cloudwatch_event_bus' resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/eventbridge-controls.html#eventbridge-3 for more details."
  }
}