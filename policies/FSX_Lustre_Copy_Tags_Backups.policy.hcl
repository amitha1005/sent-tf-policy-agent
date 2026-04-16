# FSx Lustre Copy Tags to Backups Policy
#
# This policy requires resources of type `aws_fsx_lustre_file_system` to have 
# the `copy_tags_to_backups` attribute set to true.
#
# Converted from Sentinel Policy
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/fsx-controls.html#fsx-2
#
# Resources checked:
# - aws_fsx_lustre_file_system
#
# Policy Name: fsx-lustre-copy-tags-to-backups

policy {}

resource_policy "aws_fsx_lustre_file_system" "copy_tags_to_backups" {

  enforcement_level = "advisory"
    locals {
        # Safely extract copy_tags_to_backups value, defaulting to false if not set
        copy_tags_enabled = core::try(attrs.copy_tags_to_backups, false)
    }

    enforce {
        condition = local.copy_tags_enabled == true
  error_message = "Attributes 'copy_tags_to_backups' must be true for 'aws_fsx_lustre_file_system' resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/fsx-controls.html#fsx-2 for more details."
    }
}