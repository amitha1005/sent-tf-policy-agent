# LIMITATION: This policy validates CloudFront distributions with S3 origins have OAC configured
# by matching attribute values in the planned state, but cannot verify configuration-level
# references. The original Sentinel policy uses tfconfig reference metadata to trace which
# aws_cloudfront_origin_access_control resource is referenced. TF Policy cannot access this
# metadata, so this implementation:
# 1. Checks that origin_access_control_id is configured (not null/empty)
# 2. Uses core::getresources() to find OAC resources with origin_access_control_origin_type = "s3"
# 3. Validates that at least one such OAC exists in the configuration
#
# This approach works for most cases but has limitations:
# - New resources with unresolved references may not match reliably
# - Cannot verify the specific OAC resource referenced by each distribution
# - Relies on attribute value matching rather than configuration references
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html#cloudfront-13

policy {}

# Cache S3-type OAC resources at top level for O(1) access
locals {
  # Find all aws_cloudfront_origin_access_control resources with origin_access_control_origin_type = "s3"
  s3_oac_resources = core::getresources("aws_cloudfront_origin_access_control", {
    origin_access_control_origin_type = "s3"
  })
  
  # Build a set of OAC IDs for fast lookup
  s3_oac_ids = [for oac in local.s3_oac_resources : oac.id]
  
  # Also collect OAC names as fallback
  s3_oac_names = [for oac in local.s3_oac_resources : oac.name]
}

resource_policy "aws_cloudfront_distribution" "s3_origin_access_control_enabled" {
  # Only check distributions that have origin blocks configured
  filter = attrs.origin != null && core::length(attrs.origin) > 0
  
  locals {
    # Extract all origins
    origins = attrs.origin
    
    # Check each origin for origin_access_control_id configuration
    origins_with_oac = [
      for origin in local.origins :
      origin if core::try(origin.origin_access_control_id, null) != null &&
                core::try(origin.origin_access_control_id, "") != ""
    ]
    
    # Identify potential S3 origins by checking if they don't have custom_origin_config
    # S3 origins typically use s3_origin_config or neither (just domain_name)
    # Custom origins always have custom_origin_config
    potential_s3_origins = [
      for origin in local.origins :
      origin if core::try(origin.custom_origin_config, null) == null
    ]
    
    has_potential_s3_origin = core::length(local.potential_s3_origins) > 0
    
    # For origins that might be S3, check if they have OAC configured
    s3_origins_with_oac = [
      for origin in local.potential_s3_origins :
      origin if core::try(origin.origin_access_control_id, null) != null &&
                core::try(origin.origin_access_control_id, "") != ""
    ]
    
    # Check if there are any S3-type OACs in the configuration
    has_s3_oac_in_config = core::length(local.s3_oac_ids) > 0
    
    # All potential S3 origins should have OAC configured
    all_s3_have_oac = core::length(local.potential_s3_origins) == core::length(local.s3_origins_with_oac)
  }
  
  enforce {
    # If distribution has potential S3 origins, they must have OAC configured
    # AND S3-type OAC resources must exist in the configuration
    condition = !local.has_potential_s3_origin || (local.all_s3_have_oac && local.has_s3_oac_in_config)
    error_message = "'aws_cloudfront_distribution' with an Amazon S3 origin must have 'aws_cloudfront_origin_access_control' configured with origin_access_control_origin_type = 's3'. This distribution has ${core::length(local.potential_s3_origins)} potential S3 origin(s), ${core::length(local.s3_origins_with_oac)} with OAC configured, and ${core::length(local.s3_oac_ids)} S3-type OAC resource(s) in configuration. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html#cloudfront-13 for more details."
  }
}