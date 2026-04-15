# WorkSpaces Root Volume Encryption Policy
#
# This policy ensures that Amazon WorkSpaces WorkSpace root volumes are encrypted at rest.
# 
# Converted from Sentinel Policy:
# - Original policy checks that root_volume_encryption_enabled attribute is set to true
# - Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/workspaces-controls.html#workspaces-2
#
# Resources checked:
# - aws_workspaces_workspace
#
# Compliance: AWS Security Hub - WorkSpaces.2

policy {}

resource_policy "aws_workspaces_workspace" "root_volume_encryption_enabled" {

  enforcement_level = "advisory"
    locals {
        # Safely access root_volume_encryption_enabled attribute
        # Default to false if not set (missing attribute = violation)
        encryption_enabled = core::try(attrs.root_volume_encryption_enabled, false)
    }
    
    enforce {
        condition = local.encryption_enabled == true
        error_message = "Attribute 'root_volume_encryption_enabled' must be set to true for 'aws_workspaces_workspace' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/workspaces-controls.html#workspaces-2 for more details."
    }
}