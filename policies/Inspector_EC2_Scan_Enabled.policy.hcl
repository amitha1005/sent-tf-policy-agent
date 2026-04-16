# Amazon Inspector EC2 Scanning Enabled
#
# This policy ensures that Amazon Inspector EC2 scanning is enabled by verifying
# that aws_inspector2_enabler resources include "EC2" in their resource_types.
#
# Original Sentinel Policy: inspector-ec2-scan-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/inspector-controls.html#inspector-1
#
# Resources checked:
# - aws_inspector2_enabler

policy {}

resource_policy "aws_inspector2_enabler" "ec2_scanning_enabled" {

  enforcement_level = "advisory"
    locals {
        # Safely extract resource_types with fallback to empty list
        resource_types = core::try(attrs.resource_types, [])
        
        # Check if EC2 is included in resource_types
        ec2_enabled = core::contains(local.resource_types, "EC2")
    }
    
    enforce {
        condition = local.ec2_enabled
  error_message = "Amazon Inspector EC2 scanning should be enabled. Resource must include 'EC2' in resource_types. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/inspector-controls.html#inspector-1 for more details."
    }
}