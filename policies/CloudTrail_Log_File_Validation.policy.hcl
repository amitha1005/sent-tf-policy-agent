# CloudTrail Log File Validation Enabled Policy
#
# Converted from Sentinel policy: cloudtrail-log-file-validation-enabled
#
# This policy ensures that all AWS CloudTrail resources have log file validation 
# enabled to maintain the integrity of CloudTrail logs. Log file validation 
# provides additional assurance that log files have not been modified after 
# CloudTrail delivered them.
#
# Resources checked:
# - aws_cloudtrail
#
# Compliance Reference:
# - AWS Best Practice for CloudTrail log integrity

policy {}

resource_policy "aws_cloudtrail" "log_file_validation" {
    locals {
        # Safe access to enable_log_file_validation attribute
        # Defaults to false if not set (matching Sentinel behavior)
        validation_enabled = core::try(attrs.enable_log_file_validation, false)
    }

    enforce {
        condition = local.validation_enabled == true
        error_message = "Attribute 'enable_log_file_validation' must be true for 'aws_cloudtrail'. Enable log file validation to ensure CloudTrail log integrity."
    }
}
