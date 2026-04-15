policy {}

# Athena Workgroup CloudWatch Metrics Logging Policy
#
# This policy ensures that all AWS Athena workgroups have CloudWatch metrics 
# publishing enabled to monitor and log workgroup activities.
#
# Converted from Sentinel policy: athena-workgroup-should-have-logging-enabled
# AWS Security Hub Control: Athena.4
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/athena-controls.html#athena-4
#
# Resources checked:
# - aws_athena_workgroup
#
# Requirements:
# - The configuration block must exist
# - The publish_cloudwatch_metrics_enabled attribute must be set to true

resource_policy "aws_athena_workgroup" "cloudwatch_metrics_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get the configuration block (should be a list with one element)
        configuration_block = core::try(attrs.configuration, [])
        
        # Check if configuration block exists and is not empty
        has_configuration = core::length(local.configuration_block) > 0
        
        # Get the publish_cloudwatch_metrics_enabled value from the first configuration block
        # Default to false if not set
        cloudwatch_enabled = local.has_configuration ? core::try(local.configuration_block[0].publish_cloudwatch_metrics_enabled, false) : false
    }
    
    # Enforce that configuration block exists
    enforce {
        condition = local.has_configuration
        error_message = "Athena workgroup must have a 'configuration' block defined. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/athena-controls.html#athena-4 for more details."
    }
    
    # Enforce that publish_cloudwatch_metrics_enabled is set to true
    enforce {
        condition = local.cloudwatch_enabled == true
        error_message = "Attribute 'publish_cloudwatch_metrics_enabled' must be set to 'true' for Athena workgroup. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/athena-controls.html#athena-4 for more details."
    }
}