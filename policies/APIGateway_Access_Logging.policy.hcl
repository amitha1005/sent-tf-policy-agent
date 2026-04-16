# API Gateway Access Logging Configuration Policy
#
# This policy ensures that Amazon API Gateway Version 2 stages have access logging
# configured to enable monitoring and auditing of API requests.
#
# Converted from Sentinel policy: api-gateway-access-logging-should-be-configured
#
# Resources checked:
# - aws_apigatewayv2_stage
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html#apigateway-9

policy {}

resource_policy "aws_apigatewayv2_stage" "access_logging_configured" {

  enforcement_level = "advisory"
    locals {
        # Safely access access_log_settings, default to empty list if not present
        access_log_settings = core::try(attrs.access_log_settings, [])
        
        # Check if access_log_settings is configured (non-empty)
        has_access_logging = core::length(local.access_log_settings) > 0
    }
    
    enforce {
        condition = local.has_access_logging
  error_message = "'aws_apigatewayv2_stage' resource must have access logging configured. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html#apigateway-9 for more details."
    }
}