# EMR Block Public Access Configuration Policy
#
# This policy enforces that EMR Block Public Access is enabled with strict port restrictions.
# Block public access must be enabled and only port 22 should be permitted if any ports are allowed.
#
# Converted from Sentinel Policy: emr-block-public-access-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/emr-controls.html#emr-2
#
# Resources checked:
# - aws_emr_block_public_access_configuration

policy {}

resource_policy "aws_emr_block_public_access_configuration" "block_public_access" {

  enforcement_level = "advisory"
    locals {
        # Check if block_public_security_group_rules is set to true (required)
        block_rules_enabled = core::try(attrs.block_public_security_group_rules, false)
        
        # Get permitted rule ranges (default to empty list if not defined)
        permitted_ranges = core::try(attrs.permitted_public_security_group_rule_range, [])
        
        # Check if any permitted range allows ports other than 22
        # A valid range must have both min_range = 22 AND max_range = 22
        invalid_ranges = [
            for range in local.permitted_ranges :
            range if core::try(range.min_range, 0) != 22 || core::try(range.max_range, 0) != 22
        ]
        
        # Policy passes if:
        # 1. block_public_security_group_rules is true
        # 2. No invalid port ranges exist (all ranges must be 22-22)
        has_invalid_ports = core::length(local.invalid_ranges) > 0
    }
    
    enforce {
        condition = local.block_rules_enabled && !local.has_invalid_ports
        error_message = "Attribute 'block_public_security_group_rules' must have been set to true and any port other than 22 should not be allowed for 'aws_emr_block_public_access_configuration' resources. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/emr-controls.html#emr-2 for more details."
    }
}