# CloudTrail.5 - CloudTrail trails should be integrated with Amazon CloudWatch Logs
#
# This policy enforces that CloudTrail trails are configured to send logs to CloudWatch Logs.
# The control fails if the CloudWatchLogsLogGroupArn property of the trail is empty.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5
# Compliance Frameworks: PCI DSS v3.2.1, CIS AWS Foundations Benchmark
# Severity: Medium
# Category: Identify > Logging
#
# Resources checked:
# - aws_cloudtrail

policy {}

resource_policy "aws_cloudtrail" "cloudwatch_logs_integration" {
    locals {
        # Extract CloudWatch Logs configuration
        # Both cloud_watch_logs_group_arn and cloud_watch_logs_role_arn are checked
        # The cloud_watch_logs_group_arn must include the ":*" wildcard suffix as required by CloudTrail API
        cw_logs_group_arn = core::try(attrs.cloud_watch_logs_group_arn, null)
        cw_logs_role_arn = core::try(attrs.cloud_watch_logs_role_arn, null)
        
        # Check if CloudWatch Logs integration is properly configured
        # Both ARNs must be present and non-empty for proper integration
        has_cw_logs_group = local.cw_logs_group_arn != null && local.cw_logs_group_arn != ""
        has_cw_logs_role = local.cw_logs_role_arn != null && local.cw_logs_role_arn != ""
        
        # CloudWatch Logs integration requires both the log group ARN and role ARN
        is_integrated = local.has_cw_logs_group && local.has_cw_logs_role
    }
    
    enforce {
        condition = local.is_integrated
        error_message = "CloudTrail trail '${meta.address}' must be integrated with Amazon CloudWatch Logs. Both 'cloud_watch_logs_group_arn' and 'cloud_watch_logs_role_arn' must be configured. Sending CloudTrail logs to CloudWatch Logs facilitates real-time and historic activity logging. Refer to https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html for remediation guidance."
    }
}