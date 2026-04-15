resource "aws_appsync_api_cache" "validation_test" {
  api_id               = "test-api-id"
  api_caching_behavior = "FULL_REQUEST_CACHING"
  type                 = "SMALL"
  ttl                  = 3600
  
  # The attribute we need to validate for the policy
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
}