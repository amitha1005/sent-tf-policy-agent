# LIMITATION: This policy matches resources by attribute values in planned state,
# but cannot verify configuration-level references. The original Sentinel policy
# uses tfconfig references to reliably track which firewall each logging configuration
# is associated with. This TF Policy implementation uses core::getresources() to
# find logging configurations and match them by firewall ARN attribute values.
# However, when a new aws_networkfirewall_logging_configuration resource references
# a new aws_networkfirewall_firewall using a reference expression (e.g.,
# aws_networkfirewall_firewall.example.arn), the reference may not be resolved at
# policy evaluation time, causing the match to fail even though the configuration
# is correct.

# Network Firewall Logging Enabled
#
# This policy ensures that AWS Network Firewall resources have logging enabled
# by checking that each aws_networkfirewall_firewall has an associated
# aws_networkfirewall_logging_configuration resource.
#
# Resources checked:
# - aws_networkfirewall_firewall
#
# Reference:
# https://docs.aws.amazon.com/securityhub/latest/userguide/networkfirewall-controls.html#networkfirewall-2

policy {}

resource_policy "aws_networkfirewall_firewall" "logging_enabled" {

  enforcement_level = "advisory"
  locals {
    # Get all aws_networkfirewall_logging_configuration resources
    all_logging_configs = core::getresources("aws_networkfirewall_logging_configuration", {})
    
    # Extract firewall ARNs from logging configurations
    # Note: Attributes from getresources are at top level (config.firewall_arn, not config.attrs.firewall_arn)
    logged_firewall_arns = [
      for config in local.all_logging_configs :
      config.firewall_arn if config.firewall_arn != null
    ]
    
    # Get the ARN of the current firewall being evaluated
    firewall_arn = core::try(attrs.arn, null)
    
    # Check if this firewall's ARN is in the list of logged firewalls
    has_logging = local.firewall_arn != null && core::contains(local.logged_firewall_arns, local.firewall_arn)
  }
  
  enforce {
    condition     = local.has_logging
    error_message = "'aws_networkfirewall_firewall' resource should have logging enabled. Create an 'aws_networkfirewall_logging_configuration' resource that references this firewall's ARN. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/networkfirewall-controls.html#networkfirewall-2 for more details."
  }
}