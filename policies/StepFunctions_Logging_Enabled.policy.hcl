# AWS Step Functions State Machine Logging Enabled
#
# This policy ensures AWS Step Functions state machines have logging configuration
# enabled with level set to "ALL", "ERROR", or "FATAL".
#
# Converted from Sentinel Policy: sfn-logging-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/stepfunctions-controls.html#stepfunctions-1
#
# Resources checked:
# - aws_sfn_state_machine

policy {}

resource_policy "aws_sfn_state_machine" "logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Valid log levels according to policy requirements
        required_log_levels = ["ALL", "ERROR", "FATAL"]
        
        # Safely extract logging configuration
        logging_config = core::try(attrs.logging_configuration, null)
        
        # Check if logging configuration exists and is not empty
        has_logging_config = local.logging_config != null ? core::length(local.logging_config) > 0 : false
        
        # Extract log level from logging configuration
        log_level = local.has_logging_config ? core::try(local.logging_config[0].level, null) : null
        
        # Check if log level is one of the required values
        is_valid_log_level = local.log_level != null ? core::contains(local.required_log_levels, local.log_level) : false
    }
    
    enforce {
        condition = local.is_valid_log_level
        error_message = "AWS Step Functions state machine must have logging enabled with level set to 'ALL', 'ERROR', or 'FATAL'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/stepfunctions-controls.html#stepfunctions-1 for more details."
    }
}