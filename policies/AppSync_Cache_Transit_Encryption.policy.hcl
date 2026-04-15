# AppSync Cache Transit Encryption Policy
#
# This policy ensures that AWS AppSync API Cache resources have transit encryption enabled.
# Transit encryption protects data in transit between the application and the cache.
#
# Resources checked:
# - aws_appsync_api_cache
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/appsync-controls.html#appsync-6
#
# Converted from Sentinel policy: appsync-cache-should-be-encrypted-at-transit

policy {}

resource_policy "aws_appsync_api_cache" "transit_encryption_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get transit_encryption_enabled attribute, default to false if not set
        transit_encryption_enabled = core::try(attrs.transit_encryption_enabled, false)
    }

    enforce {
        condition = local.transit_encryption_enabled == true
        error_message = "Attribute 'transit_encryption_enabled' must be set to 'true' for 'aws_appsync_api_cache' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/appsync-controls.html#appsync-6 for more details."
    }
}