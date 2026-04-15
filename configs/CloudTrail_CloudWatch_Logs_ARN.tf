provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudtrail" "validation_test" {
  name                          = "test-trail"
  s3_bucket_name                = "test-bucket"
  cloud_watch_logs_group_arn    = "arn:aws:logs:us-east-1:123456789012:log-group:test-group:*"
  cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/test-role"
  enable_log_file_validation    = true
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = false
}