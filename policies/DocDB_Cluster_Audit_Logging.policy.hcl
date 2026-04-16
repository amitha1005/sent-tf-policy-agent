# DocumentDB Cluster Audit Logging Enabled
#
# This policy ensures that AWS DocumentDB clusters have audit logging enabled
# by verifying that the `enabled_cloudwatch_logs_exports` attribute contains "audit".
#
# Converted from Sentinel Policy: docdb-cluster-audit-logging-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/documentdb-controls.html#documentdb-4
#
# Resources checked:
# - aws_docdb_cluster
#
# Compliance:
# - AWS Security Hub: DocumentDB.4

policy {}

resource_policy "aws_docdb_cluster" "audit_logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get the enabled_cloudwatch_logs_exports attribute
        # If null or missing, default to empty list to avoid null errors
        cloudwatch_logs_exports = attrs.enabled_cloudwatch_logs_exports != null ? attrs.enabled_cloudwatch_logs_exports : []
        
        # Check if the list contains "audit"
        has_audit_logging = core::contains(local.cloudwatch_logs_exports, "audit")
    }
    
    enforce {
        condition = local.has_audit_logging
  error_message = "Attribute 'enabled_cloudwatch_logs_exports' should be 'audit' for AWS DocumentDb Cluster. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/documentdb-controls.html#documentdb-4 for more details."
    }
}