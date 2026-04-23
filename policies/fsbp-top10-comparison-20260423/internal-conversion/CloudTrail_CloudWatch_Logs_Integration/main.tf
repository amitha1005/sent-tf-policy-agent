provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudtrail" "validation_test" {
  name                          = "test-trail"
  s3_bucket_name                = "test-bucket"
  cloud_watch_logs_group_arn    = "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group:*"
  cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/test-role"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}

resource "aws_cloudwatch_log_group" "validation_test" {
  name              = "test-log-group"
  retention_in_days = 30
}