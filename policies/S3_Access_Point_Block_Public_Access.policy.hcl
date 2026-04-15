# S3 Access Point Block Public Access Enabled
#
# This policy ensures that all AWS S3 Access Points have all attributes
# in the public_access_block_configuration set to true to prevent public access.
#
# Converted from Sentinel policy: s3-access-point-block-public-access-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-19
#
# Resource checked: aws_s3_access_point

policy {}

resource_policy "aws_s3_access_point" "block_public_access_enabled" {

  enforcement_level = "advisory"
    locals {
        # Extract public_access_block_configuration (list of objects)
        public_access_block = core::try(attrs.public_access_block_configuration, [])
        
        # Check if configuration exists
        has_config = core::length(local.public_access_block) > 0
        
        # Extract individual attributes with safe defaults
        block_public_acls = local.has_config ? core::try(local.public_access_block[0].block_public_acls, false) : false
        ignore_public_acls = local.has_config ? core::try(local.public_access_block[0].ignore_public_acls, false) : false
        block_public_policy = local.has_config ? core::try(local.public_access_block[0].block_public_policy, false) : false
        restrict_public_buckets = local.has_config ? core::try(local.public_access_block[0].restrict_public_buckets, false) : false
        
        # All must be true
        all_enabled = local.block_public_acls == true && local.ignore_public_acls == true && local.block_public_policy == true && local.restrict_public_buckets == true
    }

    enforce {
        condition = local.has_config
        error_message = "S3 Access Point '${meta.address}' does not have 'public_access_block_configuration' defined. All attributes in 'public_access_block_configuration' must be set to true. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-19 for more details."
    }

    enforce {
        condition = local.all_enabled
        error_message = "S3 Access Point '${meta.address}' does not have all attributes in 'public_access_block_configuration' set to true. All of block_public_acls, ignore_public_acls, block_public_policy, and restrict_public_buckets must be true. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-19 for more details."
    }
}