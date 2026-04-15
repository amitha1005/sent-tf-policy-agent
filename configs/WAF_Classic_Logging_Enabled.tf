provider "aws" {
  region = "us-east-1"
}

# Test resource for aws_waf_web_acl validation
resource "aws_waf_web_acl" "validation_test" {
  name        = "validation-test-acl"
  metric_name = "validationTestAcl"

  default_action {
    type = "ALLOW"
  }

  # Testing the logging_configuration attribute
  logging_configuration {
    log_destination = "arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-test"
  }
}

# Test resource for aws_kinesis_firehose_delivery_stream validation
resource "aws_kinesis_firehose_delivery_stream" "validation_test" {
  name        = "aws-waf-logs-validation-test"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = "arn:aws:iam::123456789012:role/firehose-role"
    bucket_arn = "arn:aws:s3:::test-bucket"
  }
}