resource "aws_cloudwatch_log_group" "example" {
  name = "example-es-audit-logs"
}

data "aws_iam_policy_document" "example" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
    actions = [
      "logs:PutLogEvents",
      "logs:PutLogEventsBatch",
      "logs:CreateLogStream",
    ]
    resources = ["arn:aws:logs:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "example" {
  policy_name     = "example"
  policy_document = data.aws_iam_policy_document.example.json
}

resource "aws_elasticsearch_domain" "validation_test" {
  domain_name           = "example"
  elasticsearch_version = "7.10"

  # Test the log_publishing_options attribute with audit logs
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
    enabled                  = true
  }
}