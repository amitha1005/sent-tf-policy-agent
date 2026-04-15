# OpenSearch Access Control Enabled
#
# This policy ensures that AWS OpenSearch domains have Fine-Grained Access Control
# properly enabled by verifying both advanced_security_options.enabled and
# advanced_security_options.anonymous_auth_enabled are set to true.
#
# Converted from Sentinel policy: opensearch-access-control-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/opensearch-controls.html#opensearch-7
#
# Resources checked:
# - aws_opensearch_domain

policy {}

resource_policy "aws_opensearch_domain" "access_control_enabled" {

  enforcement_level = "advisory"
    locals {
        # Safely access advanced_security_options block
        advanced_security_options = core::try(attrs.advanced_security_options, [])
        
        # Check if the block exists and is not empty
        has_advanced_security_options = core::length(local.advanced_security_options) > 0
        
        # Extract enabled and anonymous_auth_enabled from the first block element
        enabled = local.has_advanced_security_options ? core::try(local.advanced_security_options[0].enabled, false) : false
        anonymous_auth_enabled = local.has_advanced_security_options ? core::try(local.advanced_security_options[0].anonymous_auth_enabled, false) : false
        
        # Both must be true for Fine-Grained Access Control
        access_control_properly_configured = local.enabled == true && local.anonymous_auth_enabled == true
    }
    
    enforce {
        condition = local.access_control_properly_configured
        error_message = "Attribute 'anonymous_auth_enabled' in 'advanced_security_options' should be true and 'advanced_security_options' should be enabled for Fine Grained Access Control for AWS OpenSearch Domain '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/opensearch-controls.html#opensearch-7 for more details."
    }
}