# Neptune Cluster Audit Logs Publishing Enabled
#
# This policy ensures that all AWS Neptune clusters have audit logs publishing
# enabled to CloudWatch Logs for security monitoring and compliance purposes.
#
# Resources checked:
# - aws_neptune_cluster
#
# Compliance Reference:
# - AWS Security Hub FSBP Neptune.2
# - https://docs.aws.amazon.com/securityhub/latest/userguide/neptune-controls.html#neptune-2
#
# Converted from Sentinel Policy: neptune-cluster-audit-logs-publishing-enabled

policy {}

resource_policy "aws_neptune_cluster" "audit_logs_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get the enable_cloudwatch_logs_exports attribute, default to empty list if not set
        cloudwatch_logs_exports = core::try(attrs.enable_cloudwatch_logs_exports, [])
        
        # Check if "audit" is included in the list
        audit_enabled = core::contains(local.cloudwatch_logs_exports, "audit")
    }
    
    enforce {
        condition = local.audit_enabled
        error_message = "Attribute 'enable_cloudwatch_logs_exports' must contain 'audit' for 'aws_neptune_cluster' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/neptune-controls.html#neptune-2 for more details."
    }
}