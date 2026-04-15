# EFS Access Point Should Enforce Root Directory
#
# This policy ensures that AWS EFS access points enforce a specific subdirectory
# rather than exposing the entire root file system. The policy checks that if
# root_directory is specified, the path attribute must not be set to "/".
#
# Converted from Sentinel policy: efs-access-point-should-enforce-root-directory
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/efs-controls.html#efs-3
#
# Resources checked:
# - aws_efs_access_point

policy {}

resource_policy "aws_efs_access_point" "enforce_root_directory" {

  enforcement_level = "advisory"
    locals {
        # Safely check if root_directory block exists and is not empty
        root_directory = core::try(attrs.root_directory, [])
        has_root_directory = core::length(local.root_directory) > 0
        
        # Safely get the path value from root_directory
        # If root_directory exists, check the path; if root_directory doesn't exist, this is valid (returns empty string)
        root_path = local.has_root_directory ? core::try(local.root_directory[0].path, "") : ""
        
        # The policy should flag violations when root_directory.path is explicitly set to "/"
        # Allow: root_directory not specified (null/empty) - returns true
        # Allow: root_directory specified but path is not "/" - returns true
        # Violation: root_directory.path is set to "/" - returns false
        is_compliant = !local.has_root_directory || local.root_path != "/"
    }

    enforce {
        condition     = local.is_compliant
        error_message = "Attribute 'path' should not be '/' in 'root_directory' for 'aws_efs_access_point' resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/efs-controls.html#efs-3 for more details."
    }
}