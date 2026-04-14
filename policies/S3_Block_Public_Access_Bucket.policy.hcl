# LIMITATION:
# This policy matches S3 buckets to public access block resources by attribute values
# in the planned state, but cannot verify configuration-level references. The original
# Sentinel policy uses config metadata (constant_value, references) to navigate
# relationships, which is not available in TF Policy. This implementation validates
# that buckets have corresponding public access blocks with matching bucket attributes,
# but cannot guarantee the reference relationship in the configuration.

policy {}

resource_policy "aws_s3_bucket" "block_public_access" {
  locals {
    # Get all public access block resources
    all_public_access_blocks = core::getresources("aws_s3_bucket_public_access_block", {})
    
    # Filter to only those with all 4 settings enabled
    compliant_public_access_blocks = [
      for pab in local.all_public_access_blocks :
      pab if (
        core::try(pab.block_public_acls, false) == true &&
        core::try(pab.block_public_policy, false) == true &&
        core::try(pab.ignore_public_acls, false) == true &&
        core::try(pab.restrict_public_buckets, false) == true
      )
    ]
    
    # Build a list of bucket identifiers that have compliant public access blocks
    compliant_bucket_names = [
      for pab in local.compliant_public_access_blocks :
      core::try(pab.bucket, "")
    ]
    
    # Check if this bucket has a compliant public access block
    bucket_name = core::try(attrs.bucket, "")
    bucket_id = core::try(attrs.id, local.bucket_name)
    
    # Check if either the bucket name or id is in our compliant list
    has_compliant_block = (
      core::contains(local.compliant_bucket_names, local.bucket_name) ||
      core::contains(local.compliant_bucket_names, local.bucket_id)
    )
  }
  
  enforce {
    condition = local.has_compliant_block
    error_message = "Bucket level Amazon S3 block public access settings are not compliant for bucket '${core::try(attrs.bucket, "unknown")}'. All four settings (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets) must be set to true in the corresponding aws_s3_bucket_public_access_block resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-8 for more details."
  }
}
