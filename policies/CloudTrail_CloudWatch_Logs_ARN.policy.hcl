# LIMITATION: This policy validates that cloud_watch_logs_group_arn is configured in the
# planned state, but cannot verify if the value is a constant or a variable reference.
# The original Sentinel policy checked for "constant_value" metadata which is not available
# in Terraform Policy (TF Policy has no access to config-level metadata like constant_value,
# references, or expressions).
#
# CloudTrail CloudWatch Logs Group ARN Policy
#
# This policy ensures that AWS CloudTrail resources have the cloud_watch_logs_group_arn
# attribute configured. CloudTrail trails must send logs to CloudWatch Logs for centralized
# log monitoring, analysis, and alerting capabilities.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5
#
# Converted from Sentinel policy: cloudtrail-cloudwatch-logs-group-arn-present
#
# Resources checked:
# - aws_cloudtrail

policy {}

resource_policy "aws_cloudtrail" "cloudwatch_logs_group_arn" {

  enforcement_level = "advisory"
    locals {
        # Check if cloud_watch_logs_group_arn is configured and not empty
        # Using core::try to safely handle cases where attribute might not be present
        logs_group_arn = core::try(attrs.cloud_watch_logs_group_arn, null)
        
        # Attribute must be present (not null) and not empty string
        is_configured = local.logs_group_arn != null && local.logs_group_arn != ""
    }

    enforce {
        condition = local.is_configured
        error_message = "Attribute 'cloud_watch_logs_group_arn' must be present for 'aws_cloudtrail' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5 for more details."
    }
}