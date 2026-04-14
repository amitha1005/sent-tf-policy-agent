# LIMITATION: This policy has significant constraints due to TF Policy's technical limitations.
#
# The original Sentinel policy validates cross-resource relationships by:
# 1. Navigating from aws_s3_bucket_policy to referenced aws_iam_policy_document data sources
# 2. Inspecting the data source's statement conditions for SSL enforcement
# 3. Mapping buckets to their policies using reference metadata
#
# TF Policy Constraints:
# - Cannot access res.config.attribute["references"] metadata
# - Cannot navigate from bucket_policy.policy to the referenced data source
# - Can only match resources by attribute values in planned state
# - Cannot parse JSON strings or use regex for pattern matching
# - New resources with unresolved references may not match reliably
#
# This implementation:
# - Validates that S3 buckets have associated bucket policies (by matching bucket identifiers)
# - Validates that bucket policies have policy content
# - CANNOT verify SSL enforcement conditions in the policy document
# - CANNOT verify that policies reference aws_iam_policy_document data sources
#
# For complete validation matching the original Sentinel policy, use Sentinel or OPA with tfconfig access.

policy {}

# Top-level locals for performance optimization
locals {
  # Get all bucket policies once instead of per-bucket
  all_bucket_policies = core::getresources("aws_s3_bucket_policy", {})
  
  # Create a list of bucket identifiers that have policies
  buckets_with_policies = [
    for policy in local.all_bucket_policies :
    policy.bucket
  ]
}

# Check that S3 buckets have associated bucket policies
resource_policy "aws_s3_bucket" "has_bucket_policy" {
  locals {
    # Get bucket identifier - could be bucket name, bucket ARN, or reference
    bucket_name = core::try(attrs.bucket, "")
    bucket_id = core::try(attrs.id, "")
    
    # Check if this bucket has an associated bucket policy
    # This matches by attribute value, which works for explicit names
    # but may miss references that aren't resolved yet
    has_policy_by_name = core::contains(local.buckets_with_policies, local.bucket_name)
    has_policy_by_id = core::contains(local.buckets_with_policies, local.bucket_id)
    has_policy = local.has_policy_by_name || local.has_policy_by_id
  }
  
  enforce {
    condition = local.has_policy
    error_message = "S3 bucket must have an associated aws_s3_bucket_policy resource that enforces SSL. The bucket policy should deny requests when aws:SecureTransport is false. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-5 for more details."
  }
}

# Check that bucket policies have policy content
resource_policy "aws_s3_bucket_policy" "has_policy_content" {
  locals {
    # Verify the policy attribute has content
    policy_content = core::try(attrs.policy, null)
    has_content = local.policy_content != null && local.policy_content != ""
  }
  
  enforce {
    condition = local.has_content
    error_message = "Bucket policy must have a policy document defined. Best practice: use aws_iam_policy_document data source to define policies with SSL enforcement (Deny effect when aws:SecureTransport is false)."
  }
}