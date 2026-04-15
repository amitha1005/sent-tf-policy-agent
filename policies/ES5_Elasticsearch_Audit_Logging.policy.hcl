# Elasticsearch Domain Audit Logging Enabled (ES.5)
#
# This policy ensures that AWS Elasticsearch domains have audit logging enabled
# by requiring log_publishing_options with enabled=true and log_type=AUDIT_LOGS.
#
# Converted from Sentinel policy: elasticsearch-audit-logging-enabled
# AWS Security Hub Control: ES.5
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/es-controls.html#es-5
#
# Resources checked:
# - aws_elasticsearch_domain

policy {}

resource_policy "aws_elasticsearch_domain" "audit_logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get log_publishing_options as a list (may be null or empty)
        log_options = core::try(attrs.log_publishing_options, [])
        
        # Filter for AUDIT_LOGS entries
        audit_log_options = [for option in local.log_options : option if core::try(option.log_type, "") == "AUDIT_LOGS"]
        
        # Check if audit logging is configured and enabled
        has_audit_logs = core::length(local.audit_log_options) > 0
        audit_logs_enabled = local.has_audit_logs ? core::try(local.audit_log_options[0].enabled, true) : false
    }
    
    # Enforce that audit logging must be configured and enabled
    enforce {
        condition = local.has_audit_logs && local.audit_logs_enabled
        error_message = "Attribute 'enabled' must be set to true and attribute 'log_type' set to 'AUDIT_LOGS' in the 'log_publishing_options' block for 'aws_elasticsearch_domain' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/es-controls.html#es-5 for more details."
    }
}