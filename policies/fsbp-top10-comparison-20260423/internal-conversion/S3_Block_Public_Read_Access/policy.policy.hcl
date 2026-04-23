# LIMITATION: This policy validates S3 bucket public access configuration but has
# the following constraints due to TF Policy limitations:
# 
# 1. Cross-resource reference validation is limited:
#    - The policy matches resources by attribute values in planned state
#    - Cannot verify configuration-level references between resources
#    - Resources with unresolved references during creation may not match reliably
#
# 2. Policy document inspection limitations:
#    - Cannot access tfconfig metadata (constant_value, references) used in Sentinel
#    - Cannot trace which data source a bucket policy references at config time
#    - Can only check if a bucket has a policy with public read actions in planned state
#
# 3. The Sentinel policy uses config-level reference navigation which is not available:
#    - Original uses policy["references"] to find referenced data sources
#    - TF Policy can only match on resolved attribute values
#
# Reference: AWS Security Hub Control S3.2
# https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2

policy {}

# Check if any bucket policies allow public read access
locals {
  # Get all bucket policies
  all_bucket_policies = core::getresources("aws_s3_bucket_policy", {})
  
  # Get all IAM policy documents
  all_policy_documents = core::getresources("aws_iam_policy_document", {})
  
  # Build a map of policy document JSON to check for public read
  policy_docs_with_public_read = {
    for doc in local.all_policy_documents :
    doc.json => true
    if core::length([
      for stmt in core::try(doc.statement, []) :
      stmt if core::try(stmt.effect, "Deny") == "Allow" && core::length([
        for action in core::try(stmt.actions, []) :
        action if core::contains([":*", "s3:GetObject", "s3:GetBucket"], action) || action == "s3:*" || action == "s3:GetObject" || action == "s3:GetBucket" || action == "s3:GetObject*" || action == "s3:GetBucket*"
      ]) > 0
    ]) > 0
  }
  
  # Build a map of bucket addresses that have policy violations
  buckets_with_policy_violations = {
    for policy in local.all_bucket_policies :
    policy.bucket => true
    if core::try(local.policy_docs_with_public_read[policy.policy], false)
  }
}

# Validate S3 buckets don't allow public read access
resource_policy "aws_s3_bucket" "block_public_read_access" {
  locals {
    # Check if this bucket has a violating policy
    has_policy_violation = core::try(local.buckets_with_policy_violations[attrs.id], false)
    
    # Get related public access block for this bucket
    related_pabs = [
      for pab in core::getresources("aws_s3_bucket_public_access_block", {}) :
      pab if pab.bucket == core::try(attrs.id, attrs.bucket)
    ]
    
    # Check if public access block is properly configured
    pab_block_public_acls = core::length(local.related_pabs) > 0 ? core::try(local.related_pabs[0].block_public_acls, false) : false
    pab_ignore_public_acls = core::length(local.related_pabs) > 0 ? core::try(local.related_pabs[0].ignore_public_acls, false) : false
    pab_block_public_policy = core::length(local.related_pabs) > 0 ? core::try(local.related_pabs[0].block_public_policy, false) : false
    pab_restrict_public_buckets = core::length(local.related_pabs) > 0 ? core::try(local.related_pabs[0].restrict_public_buckets, false) : false
    has_proper_pab = local.pab_block_public_acls && local.pab_ignore_public_acls && local.pab_block_public_policy && local.pab_restrict_public_buckets
    
    # Get related ACL for this bucket
    related_acls = [
      for acl in core::getresources("aws_s3_bucket_acl", {}) :
      acl if acl.bucket == core::try(attrs.id, attrs.bucket)
    ]
    
    # Check for violating canned ACL
    has_invalid_canned_acl = core::length(local.related_acls) > 0 ? core::contains(["public-read", "public-read-write", "authenticated-read", "aws-exec-read"], core::try(local.related_acls[0].acl, "")) : false
    
    # Check for violating access control policy grants
    grant_violations = core::length(local.related_acls) > 0 ? [
      for grant in core::try(local.related_acls[0].access_control_policy[0].grant, []) :
      grant if core::contains(["FULL_CONTROL", "READ", "READ_ACP"], core::try(grant.permission, ""))
    ] : []
    has_invalid_grant = core::length(local.grant_violations) > 0
    
    has_acl_violation = local.has_invalid_canned_acl || local.has_invalid_grant
    
    # Bucket violates if it has policy violation OR missing proper PAB OR has ACL violation
    has_violation = local.has_policy_violation || !local.has_proper_pab || local.has_acl_violation
  }
  
  enforce {
    condition = !local.has_violation
    error_message = "S3 general purpose buckets should block public read access. Ensure: (1) bucket policies don't allow public read (s3:GetObject, s3:GetBucket), (2) public access block has all four settings enabled, and (3) bucket ACLs are not set to public-read, public-read-write, authenticated-read, or aws-exec-read. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2 for more details."
  }
}

# Validate public access blocks are properly configured
resource_policy "aws_s3_bucket_public_access_block" "all_settings_enabled" {
  locals {
    block_public_acls       = core::try(attrs.block_public_acls, false)
    ignore_public_acls      = core::try(attrs.ignore_public_acls, false)
    block_public_policy     = core::try(attrs.block_public_policy, false)
    restrict_public_buckets = core::try(attrs.restrict_public_buckets, false)
    
    all_enabled = local.block_public_acls && local.ignore_public_acls && local.block_public_policy && local.restrict_public_buckets
  }
  
  enforce {
    condition = local.all_enabled
    error_message = "S3 bucket public access block must have all four settings enabled: block_public_acls, ignore_public_acls, block_public_policy, and restrict_public_buckets must all be true. Current values: block_public_acls=${local.block_public_acls}, ignore_public_acls=${local.ignore_public_acls}, block_public_policy=${local.block_public_policy}, restrict_public_buckets=${local.restrict_public_buckets}."
  }
}

# Validate bucket ACLs don't allow public access
resource_policy "aws_s3_bucket_acl" "no_public_acl" {
  locals {
    invalid_canned_acls = ["public-read", "public-read-write", "authenticated-read", "aws-exec-read"]
    invalid_permissions = ["FULL_CONTROL", "READ", "READ_ACP"]
    
    acl_value = core::try(attrs.acl, "")
    has_invalid_acl = local.acl_value != "" && core::contains(local.invalid_canned_acls, local.acl_value)
    
    # Check access control policy grants - count violations
    grant_violations = [
      for grant in core::try(attrs.access_control_policy[0].grant, []) :
      grant if core::contains(local.invalid_permissions, core::try(grant.permission, ""))
    ]
    has_invalid_grant = core::length(local.grant_violations) > 0
  }
  
  enforce {
    condition = !local.has_invalid_acl
    error_message = "S3 bucket ACL must not be set to public-read, public-read-write, authenticated-read, or aws-exec-read. Current ACL: '${local.acl_value}'."
  }
  
  enforce {
    condition = !local.has_invalid_grant
    error_message = "S3 bucket access control policy grants must not include FULL_CONTROL, READ, or READ_ACP permissions as these can allow public access."
  }
}