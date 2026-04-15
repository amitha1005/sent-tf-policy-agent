# LIMITATION: This policy can only validate that logging_role is configured in the planned state,
# but cannot verify if it uses a constant value vs reference (as the original Sentinel policy does).
# TF Policy does not have access to config-level metadata (constant_value, references, expressions).
# The policy will check that the attribute is non-null and non-empty in the planned values.

# Transfer Family Connectors Should Have Logging Enabled
#
# This policy checks whether Amazon CloudWatch logging is enabled for an AWS Transfer Family connector
# by verifying that the 'logging_role' attribute is properly configured.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/transfer-controls.html#transfer-3
#
# Resources checked:
# - aws_transfer_connector

policy {}

resource_policy "aws_transfer_connector" "logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Safely access logging_role attribute with null fallback
        logging_role_value = core::try(attrs.logging_role, null)
        
        # Check if logging_role is properly configured (non-null and non-empty)
        has_logging_role = local.logging_role_value != null && local.logging_role_value != ""
    }
    
    enforce {
        condition = local.has_logging_role
        error_message = "Transfer Family connector '${meta.address}' should have logging enabled by setting the 'logging_role' attribute. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/transfer-controls.html#transfer-3 for more details."
    }
}