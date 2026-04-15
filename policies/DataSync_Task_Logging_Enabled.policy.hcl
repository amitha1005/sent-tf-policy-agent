# LIMITATION: This policy cannot verify if cloudwatch_log_group_arn uses a constant value
# vs a variable reference, as TF Policy does not have access to config-level metadata
# (constant_value, references). The original Sentinel policy checks these fields but
# TF Policy can only validate the resolved attribute value in the planned state.

# DataSync Task Logging Enabled Policy
#
# Ensures that AWS DataSync tasks have CloudWatch logging enabled by verifying:
# 1. The cloudwatch_log_group_arn attribute is configured and not empty
# 2. The log_level within the options block is not set to 'OFF'
#
# This policy enforces AWS Security Hub FSBP control DataSync.1
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/datasync-controls.html#datasync-1

policy {}

resource_policy "aws_datasync_task" "logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Check if cloudwatch_log_group_arn is configured and not empty
        has_log_group_arn = core::try(attrs.cloudwatch_log_group_arn, null) != null && core::try(attrs.cloudwatch_log_group_arn, "") != ""
        
        # Check if options block exists
        has_options_block = core::try(attrs.options, null) != null && core::length(core::try(attrs.options, [])) > 0
        
        # Get log_level from options block (default to "OFF" if not set)
        log_level = local.has_options_block ? core::try(attrs.options[0].log_level, "OFF") : "OFF"
        
        # Check if log_level is not OFF
        log_level_enabled = local.log_level != "OFF"
        
        # Both conditions must be true
        logging_properly_configured = local.has_log_group_arn && local.has_options_block && local.log_level_enabled
    }
    
    enforce {
        condition = local.logging_properly_configured
        error_message = "Attribute 'cloudwatch_log_group_arn' must not be empty and 'log_level' must not be 'OFF' for 'aws_datasync_task' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/datasync-controls.html#datasync-1 for more details."
    }
}