resource "aws_apigatewayv2_api" "validation_api" {
  name          = "validation-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "validation_test" {
  api_id = aws_apigatewayv2_api.validation_api.id
  name   = "validation-stage"

  access_log_settings {
    destination_arn = "arn:aws:logs:us-east-1:123456789012:log-group:api-gateway-logs"
    format         = "$context.requestId"
  }
}