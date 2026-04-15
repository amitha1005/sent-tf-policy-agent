policy {}

# Ensure logging is enabled for AWS WAF Classic global web ACLs
# This policy checks whether the logging_configuration block is present
# and properly configured in aws_waf_web_acl resources.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/waf-controls.html#waf-1
#
# Converted from Sentinel policy

resource_policy "aws_waf_web_acl" "logging_enabled" {

  enforcement_level = "advisory"
  locals {
    # Safely get logging_configuration, defaulting to empty list if not present or null
    logging_config = core::try(attrs.logging_configuration, [])
    
    # Check if logging_configuration exists and is not empty
    has_logging_config = core::length(local.logging_config) > 0
  }

  enforce {
    condition = local.has_logging_config
    error_message = "Logging should be enabled for AWS WAF global web ACL. Configure the 'logging_configuration' block with a valid Kinesis Firehose Delivery Stream ARN. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/waf-controls.html#waf-1 for more details."
  }
}