# Route53 hosted zone
resource "aws_route53_zone" "validation_test" {
  name = "example.com"
}

# CloudWatch log group (must be in us-east-1 for Route53 query logs)
resource "aws_cloudwatch_log_group" "validation_test" {
  name              = "/aws/route53/example.com"
  retention_in_days = 7
}

# Route53 query log configuration
resource "aws_route53_query_log" "validation_test" {
  zone_id                  = aws_route53_zone.validation_test.zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.validation_test.arn
}