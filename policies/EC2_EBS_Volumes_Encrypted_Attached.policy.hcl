# LIMITATION: This policy has significant technical constraints compared to the original Sentinel policy.
#
# The original Sentinel policy checks TWO requirements:
# 1. EBS volumes must have encrypted = true
# 2. EBS volumes must be attached to instances
#
# TF Policy Constraints (from terraform-policy-agent-skill):
# ❌ Constraint #1: Cannot access config-level metadata (constant_value, references, expressions)
# ❌ Constraint #3: Cannot reliably validate cross-resource relationships
# ❌ Testing limitation: resource address metadata is unavailable in mock tests for resource_policy
#
# This implementation:
# ✅ IMPLEMENTED: Validates that EBS volumes have encrypted = true
# ❌ NOT IMPLEMENTED: Cannot verify volume attachment due to:
#    - resource address metadata is unavailable in mock tests (cannot identify resources)
#    - Cannot access reference metadata to trace volume_id to source volume
#    - Cross-resource matching unreliable for new resources with unresolved references
#
# EC2 EBS Volumes Must Be Encrypted
#
# This policy ensures that AWS EBS volumes are encrypted at rest.
# Note: The attachment requirement from the original Sentinel policy cannot be implemented
# due to TF Policy's technical constraints.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-3

policy {}

# Check that all EBS volumes have encryption enabled
resource_policy "aws_ebs_volume" "encryption_check" {
  enforcement_level = "advisory"
    locals {
        # Safely access encrypted attribute (defaults to false if not set)
        is_encrypted = core::try(attrs.encrypted, false)
    }

    enforce {
        condition = local.is_encrypted == true
        error_message = "Attribute 'encrypted' must be 'true' for 'aws_ebs_volume' resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-3 for more details."
    }
}