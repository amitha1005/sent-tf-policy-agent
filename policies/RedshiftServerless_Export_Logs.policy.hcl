policy {}

# Redshift Serverless Namespaces Should Export Logs to CloudWatch Logs
#
# This policy enforces that Amazon Redshift Serverless namespaces are configured
# to export both connection and user logs to Amazon CloudWatch Logs.
#
# Resources checked:
# - aws_redshiftserverless_namespace
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/redshiftserverless-controls.html#redshiftserverless-6

resource_policy "aws_redshiftserverless_namespace" "log_exports_required" {

  enforcement_level = "advisory"
    locals {
        # Get log_exports attribute, handle null by converting to empty list
        log_exports_raw = attrs.log_exports
        log_exports = local.log_exports_raw != null ? local.log_exports_raw : []
        
        # Check if both required log types are present
        has_connectionlog = core::contains(local.log_exports, "connectionlog")
        has_userlog = core::contains(local.log_exports, "userlog")
    }
    
    enforce {
        condition = local.has_connectionlog && local.has_userlog
        error_message = "Redshift Serverless namespace '${meta.address}' should export logs to CloudWatch Logs. Both 'connectionlog' and 'userlog' should be configured. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/redshiftserverless-controls.html#redshiftserverless-6 for more details."
    }
}