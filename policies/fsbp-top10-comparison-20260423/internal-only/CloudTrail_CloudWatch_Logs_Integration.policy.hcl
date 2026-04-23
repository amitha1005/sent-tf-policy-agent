# CloudTrail CloudWatch Logs Group ARN Present Policy
#
# This policy requires resources of type aws_cloudtrail to have 
# cloud_watch_logs_group_arn attribute set to a non-empty value.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5
#
# Converted from Sentinel policy
# Policy Name: cloudtrail-cloudwatch-logs-group-arn-present

policy {}

resource_policy "aws_cloudtrail" "cloudwatch_logs_group_arn_present" {
    locals {
        # Get the cloud_watch_logs_group_arn attribute, default to null if not set
        logs_group_arn = core::try(attrs.cloud_watch_logs_group_arn, null)
        
        # Check if the attribute is present and not empty
        has_valid_arn = local.logs_group_arn != null && local.logs_group_arn != ""
    }
    
    enforce {
        condition = local.has_valid_arn
        error_message = "Attribute 'cloud_watch_logs_group_arn' must be present and non-empty for 'aws_cloudtrail' resources. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5 for more details."
    }
}