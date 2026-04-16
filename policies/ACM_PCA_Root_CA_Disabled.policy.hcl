# ACM Private CA Root CA Disabled Policy
#
# This policy checks if AWS ACM Private CA has a root certificate authority (CA) that is enabled.
# The control fails if the root CA is enabled with type 'ROOT'.
#
# Converted from Sentinel Policy
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/pca-controls.html#pca-1
#
# Resources checked:
# - aws_acmpca_certificate_authority with type = "ROOT" and enabled = true

policy {}

resource_policy "aws_acmpca_certificate_authority" "root_ca_disabled" {

  enforcement_level = "advisory"
    locals {
        # Extract CA type (defaults to "SUBORDINATE" if not specified)
        ca_type = core::try(attrs.type, "SUBORDINATE")
        
        # Extract enabled status (defaults to true if not specified)
        enabled_status = core::try(attrs.enabled, true)
        
        # Violation occurs when: type = "ROOT" AND enabled = true
        is_root_and_enabled = local.ca_type == "ROOT" && local.enabled_status == true
    }
    
    enforce {
        condition = !local.is_root_and_enabled
  error_message = "Root CA must be disabled for 'aws_acmpca_certificate_authority' resource. Enablement of root CA should be avoided in production. Current configuration: type='${local.ca_type}', enabled='${local.enabled_status}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/pca-controls.html#pca-1 for more details."
    }
}