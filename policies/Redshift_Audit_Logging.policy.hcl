# LIMITATION: This policy matches resources by cluster_identifier attribute values in the planned state,
# but cannot verify configuration-level references. New aws_redshift_logging resources with unresolved
# cluster_identifier references may not match reliably until the reference is resolved.
#
# Redshift Cluster Audit Logging Enabled
#
# This policy ensures that AWS Redshift clusters have audit logging enabled.
# It checks that each aws_redshift_cluster has a corresponding aws_redshift_logging
# resource with matching cluster_identifier.
#
# Original Sentinel Policy: redshift-cluster-audit-logging-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/redshift-controls.html#redshift-4
#
# Resources checked:
# - aws_redshift_cluster: Validates each cluster has logging configured
# - aws_redshift_logging: Used to validate logging configuration exists

policy {}

resource_policy "aws_redshift_cluster" "audit_logging_enabled" {
  enforcement_level = "advisory"
  locals {
    cluster_id = attrs.cluster_identifier
    all_logging = core::getresources("aws_redshift_logging", {})
    matching_logging = [for log in local.all_logging : log if log.cluster_identifier == local.cluster_id]
    has_logging = core::length(local.matching_logging) > 0
    logging_config = local.has_logging ? local.matching_logging[0] : null
    has_valid_logging_config = local.has_logging ? (core::try(local.logging_config.log_destination_type, "") == "s3" || core::try(local.logging_config.log_destination_type, "") == "cloudwatch") : false
  }
  
  enforce {
    condition = local.has_logging
    error_message = "Parameter 'logging' should be enabled or referenced to resource AWS Redshift Logging for AWS Redshift Cluster '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/redshift-controls.html#redshift-4 for more details."
  }
  
  enforce {
    condition = !local.has_logging || local.has_valid_logging_config
    error_message = "AWS Redshift Logging configuration for cluster '${meta.address}' must have log_destination_type set to either 's3' or 'cloudwatch'. Current configuration is invalid or incomplete."
  }
}
