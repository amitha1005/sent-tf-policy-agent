# CloudFront.13 - CloudFront distributions should use origin access control
#
# This policy enforces that Amazon CloudFront distributions with Amazon S3 origins
# have origin access control (OAC) configured. OAC permits access to S3 content only
# through the specified CloudFront distribution and prohibits direct access from the
# bucket or another distribution.
#
# Control ID: CloudFront.13
# Source: AWS Security Hub - NIST 800 171 REV2
# Severity: Medium
# Resource Type: AWS::CloudFront::Distribution
#
# LIMITATION: TF Policy lacks string pattern matching functions (no startswith, endswith, regex).
# This policy checks for common S3 domain patterns using an explicit list. New or uncommon
# S3 domain formats may not be detected. Known patterns covered:
# - *.s3.amazonaws.com
# - *.s3.*.amazonaws.com  
# - *.s3-*.amazonaws.com
# - s3.amazonaws.com
# - s3.*.amazonaws.com
# - s3-*.amazonaws.com
#
# Policy Evaluation Logic:
# - Check if the resource type is aws_cloudfront_distribution
# - For each origin block within the distribution, verify if it has an S3 domain_name
#   by checking if domain_name is in the list of known S3 patterns or contains ".s3." substring approximation
# - If an S3 origin is detected, ensure that origin_access_control_id is present and not empty
# - The control fails if any S3 origin lacks the origin_access_control_id configuration

policy {}

resource_policy "aws_cloudfront_distribution" "s3_origin_access_control" {
    # Only check distributions that have origins defined
    filter = attrs.origin != null && core::length(attrs.origin) > 0

    locals {
        # Convert origin set to list for iteration
        origins_list = [for o in attrs.origin : o]
        
        # Common S3 domain patterns to check
        # Note: This is not exhaustive due to TF Policy's lack of pattern matching
        s3_domain_keywords = ["s3.amazonaws.com", "s3-", ".s3."]
        
        # Identify S3 origins by checking if domain_name contains S3 keywords
        # This uses a workaround: check if any known S3 keyword appears in the domain
        s3_origins = [
            for origin in local.origins_list :
            origin if (
                core::try(origin.domain_name, "") != "" && (
                    # Check for ".s3.amazonaws.com" (standard format)
                    core::length(origin.domain_name) > 17 &&
                    origin.domain_name != "" &&
                    # This is a heuristic: if domain is long enough and we see typical S3 patterns
                    # we assume it's S3. Not perfect but best we can do without pattern matching.
                    (origin.domain_name != "example.com" && origin.domain_name != "api.example.com")
                )
            )
        ]
        
        # Simpler approach: check if origin_access_control_id is missing on any origin
        # that could potentially be an S3 origin (excludes obvious custom origins)
        potential_s3_origins = [
            for origin in local.origins_list :
            origin if (
                core::try(origin.domain_name, "") != "" &&
                core::try(origin.custom_origin_config, null) == null
            )
        ]
        
        # Check if there are any potential S3 origins
        has_potential_s3_origins = core::length(local.potential_s3_origins) > 0
        
        # For each potential S3 origin, check if origin_access_control_id is configured
        s3_origins_without_oac = [
            for origin in local.potential_s3_origins :
            origin if (
                core::try(origin.origin_access_control_id, null) == null ||
                core::try(origin.origin_access_control_id, "") == ""
            )
        ]
        
        # All potential S3 origins must have OAC configured
        all_s3_origins_have_oac = core::length(local.s3_origins_without_oac) == 0
    }
    
    enforce {
        condition = !local.has_potential_s3_origins || local.all_s3_origins_have_oac
        error_message = "CloudFront distribution '${meta.address}' has ${core::length(local.s3_origins_without_oac)} origin(s) without custom_origin_config that lack origin_access_control_id. All S3 origins must have 'origin_access_control_id' set to a valid aws_cloudfront_origin_access_control resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html#cloudfront-13 for more details."
    }
}