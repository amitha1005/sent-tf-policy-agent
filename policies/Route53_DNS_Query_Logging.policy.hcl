# LIMITATION: This policy validates that aws_route53_query_log resources have cloudwatch_log_group_arn
# configured in the planned state, but cannot verify configuration-level references or distinguish between
# constant values, variable references, and resource references. The original Sentinel policy checked
# tfconfig metadata (constant_value, references) which is not available in Terraform Policy.
#
# Route 53 Public Hosted Zones DNS Query Logging Policy
#
# This policy ensures that DNS query logging is enabled for Amazon Route 53 public hosted zones
# by verifying that aws_route53_query_log resources have a valid cloudwatch_log_group_arn configured.
#
# Resources checked:
# - aws_route53_query_log
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/route53-controls.html#route53-2

policy {}

resource_policy "aws_route53_query_log" "dns_query_logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Check if cloudwatch_log_group_arn is configured (not null and not empty)
        cloudwatch_log_group_arn = core::try(attrs.cloudwatch_log_group_arn, null)
        
        # A valid configuration must have cloudwatch_log_group_arn set to a non-null, non-empty value
        has_valid_log_group_arn = local.cloudwatch_log_group_arn != null && local.cloudwatch_log_group_arn != ""
    }
    
    enforce {
        condition = local.has_valid_log_group_arn
  error_message = "Route 53 public hosted zones should log DNS queries. Resource does not have a valid 'cloudwatch_log_group_arn' configured. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/route53-controls.html#route53-2 for more details."
    }
}