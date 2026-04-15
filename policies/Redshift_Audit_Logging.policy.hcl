# LIMITATION: This policy can verify that aws_redshift_logging resources exist and reference
# cluster identifiers, but it cannot verify configuration-level references (i.e., whether
# aws_redshift_logging.cluster_identifier actually references the aws_redshift_cluster resource
# vs just having a matching string value). TF Policy evaluates planned values, not config metadata.
#
# Redshift Cluster Audit Logging Enabled
#
# This policy ensures that AWS Redshift clusters have audit logging enabled.
# Validates that each cluster either:
# 1. Has an associated aws_redshift_logging resource with matching cluster_identifier
# 2. (Legacy) Has a logging block with enable = true (deprecated in newer provider versions)
#
# Resources checked:
# - aws_redshift_cluster
# - aws_redshift_logging
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/redshift-controls.html#redshift-4

policy {}

# Cache all redshift logging resources for cross-resource lookup (O(1) access)
locals {
  all_logging_resources = core::getresources("aws_redshift_logging", null)
  
  # Build a map of cluster_identifier -> logging_resource for fast lookup
  # Note: Resources from getresources() have attributes at top level, not through .attrs
  logging_by_cluster = {
    for logging in local.all_logging_resources :
    core::try(logging.cluster_identifier, "") => logging
  }
}

# Check aws_redshift_cluster resources for audit logging configuration
resource_policy "aws_redshift_cluster" "audit_logging_enabled" {
  enforcement_level = "advisory"
  locals {
    # Check for legacy logging block (may not exist in newer provider versions)
    has_legacy_logging = attrs.logging != null && core::length(attrs.logging) > 0
    legacy_logging_enabled = local.has_legacy_logging ? core::try(attrs.logging[0].enable, false) : false
    
    # Check if there's a corresponding aws_redshift_logging resource
    # Use cluster_identifier to lookup in our cached map
    cluster_id = attrs.cluster_identifier
    has_logging_resource = core::try(local.logging_by_cluster[local.cluster_id], null) != null
    
    # Cluster is compliant if either method is used
    is_compliant = local.legacy_logging_enabled || local.has_logging_resource
  }
  
  enforce {
    condition = local.is_compliant
    error_message = "Parameter 'logging' should be enabled or referenced to resource AWS Redshift Logging for AWS Redshift Cluster '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/redshift-controls.html#redshift-4 for more details."
  }
}