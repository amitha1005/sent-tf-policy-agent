# Elastic Beanstalk CloudWatch Log Streaming Enabled
#
# This policy requires that AWS Elastic Beanstalk environments have CloudWatch log streaming enabled.
# This ensures proper logging and monitoring capabilities for applications.
#
# Converted from Sentinel Policy: elasticbeanstalk-cloudwatch-log-streaming-enabled
#
# Resources checked:
# - aws_elastic_beanstalk_environment
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/elasticbeanstalk-controls.html#elasticbeanstalk-3

policy {}

resource_policy "aws_elastic_beanstalk_environment" "cloudwatch_log_streaming_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get the setting blocks, defaulting to empty list if not present
        settings = core::try(attrs.setting, [])
        
        # Check if CloudWatch log streaming is enabled
        # Look for a setting with:
        # - namespace = "aws:elasticbeanstalk:cloudwatch:logs"
        # - name = "StreamLogs"
        # - value = "true"
        has_log_streaming = core::length([
            for setting in local.settings :
            setting if (
                core::try(setting.namespace, "") == "aws:elasticbeanstalk:cloudwatch:logs" &&
                core::try(setting.name, "") == "StreamLogs" &&
                core::try(setting.value, "") == "true"
            )
        ]) > 0
    }
    
    enforce {
        condition = local.has_log_streaming
  error_message = "Elastic Beanstalk environment does not have CloudWatch log streaming enabled. Add a setting block with namespace='aws:elasticbeanstalk:cloudwatch:logs', name='StreamLogs', and value='true'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elasticbeanstalk-controls.html#elasticbeanstalk-3 for more details."
    }
}