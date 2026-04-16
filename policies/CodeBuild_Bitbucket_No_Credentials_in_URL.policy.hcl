# LIMITATION: TF Policy has no regex pattern matching functions.
# This policy uses string splitting to detect the pattern "https://[^:]+:[^@]+@"
# which indicates embedded credentials in URLs. While this approach works for
# common cases, it may not catch all edge cases that a regex would detect.

# CodeBuild Bitbucket URL Should Not Contain Sensitive Credentials
#
# This policy checks whether an 'aws_codebuild_project' Bitbucket source repository URL
# contains personal access tokens or a user name and password.
#
# Converted from Sentinel policy: codebuild-bitbucket-url-should-not-contain-sensitive-credentials
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/codebuild-controls.html#codebuild-1
#
# Resources checked:
# - aws_codebuild_project (source.location)
# - aws_codebuild_project (secondary_sources.location)

policy {}

resource_policy "aws_codebuild_project" "bitbucket_url_credentials_check" {

  enforcement_level = "advisory"
    locals {
        # Check primary source
        source = core::try(attrs.source, [])
        source_location = core::length(local.source) > 0 ? core::try(local.source[0].location, "") : ""
        
        # Check if URL contains credentials pattern: https://user:pass@host
        # Split by "://" to separate protocol from the rest
        url_parts_by_protocol = core::split("://", local.source_location)
        has_protocol = core::length(local.url_parts_by_protocol) > 1
        url_after_protocol = local.has_protocol ? local.url_parts_by_protocol[1] : ""
        
        # If there's a ":" followed by "@" in the part after protocol, it likely contains credentials
        # Split by "@" - if there are 2+ parts, there's an @ sign
        parts_by_at = core::split("@", local.url_after_protocol)
        has_at_sign = core::length(local.parts_by_at) > 1
        
        # If there's an @ sign, check if the part before it contains a ":" (indicating user:pass)
        part_before_at = local.has_at_sign ? local.parts_by_at[0] : ""
        parts_by_colon = core::split(":", local.part_before_at)
        has_colon_before_at = core::length(local.parts_by_colon) > 1
        
        # Primary source has credentials if it has both : and @ in the right positions
        primary_source_has_credentials = local.has_protocol && local.has_at_sign && local.has_colon_before_at
        
        # Check secondary sources for the same pattern
        secondary_sources = core::try(attrs.secondary_sources, [])
        secondary_sources_with_credentials = [
            for source in local.secondary_sources : source
            if (
                core::length(core::split("://", core::try(source.location, ""))) > 1 &&
                core::length(core::split("@", core::split("://", core::try(source.location, ""))[1])) > 1 &&
                core::length(core::split(":", core::split("@", core::split("://", core::try(source.location, ""))[1])[0])) > 1
            )
        ]
        
        has_secondary_violations = core::length(local.secondary_sources_with_credentials) > 0
        
        # Policy passes if no credentials found in any source
        is_compliant = !local.primary_source_has_credentials && !local.has_secondary_violations
    }
    
    enforce {
        condition = local.is_compliant
  error_message = "In 'aws_codebuild_project' resource, Bitbucket source repository URL should not contain personal access tokens or a user name and password. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/codebuild-controls.html#codebuild-1 for more details."
    }
}