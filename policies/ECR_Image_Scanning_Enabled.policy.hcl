# ECR Image Scanning Enabled Policy
#
# This policy ensures that AWS Elastic Container Registry (ECR) private repositories
# have image scanning configuration enabled. The policy checks that all aws_ecr_repository
# resources have the image_scanning_configuration block present with scan_on_push set to true.
#
# Converted from Sentinel Policy: ecr-image-scanning-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/ecr-controls.html#ecr-1
#
# Resources checked:
# - aws_ecr_repository
#
# Policy Evaluation Logic:
# 1. Check if image_scanning_configuration block exists
# 2. Verify that scan_on_push attribute is set to true
# 3. Resources without proper scanning configuration are flagged as violations

policy {}

resource_policy "aws_ecr_repository" "image_scanning_enabled" {

  enforcement_level = "advisory"
    locals {
        # Extract image scanning configuration block
        # Default to empty list if not configured
        scanning_config = core::try(attrs.image_scanning_configuration, [])
        
        # Check if scanning configuration exists (non-empty)
        has_scanning_config = core::length(local.scanning_config) > 0
        
        # Extract scan_on_push value if configuration exists
        # Default to false if not set
        scan_on_push = local.has_scanning_config ? core::try(local.scanning_config[0].scan_on_push, false) : false
    }
    
    # Enforce that image_scanning_configuration block exists
    enforce {
        condition = local.has_scanning_config
  error_message = "ECR repository is missing the 'image_scanning_configuration' block. ECR private repositories should have image scanning configured. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ecr-controls.html#ecr-1 for more details."
    }
    
    # Enforce that scan_on_push is set to true
    enforce {
        condition = local.scan_on_push == true
  error_message = "ECR repository has 'scan_on_push' set to '${local.scan_on_push}'. The 'scan_on_push' attribute must be set to 'true' to enable image scanning. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ecr-controls.html#ecr-1 for more details."
    }
}