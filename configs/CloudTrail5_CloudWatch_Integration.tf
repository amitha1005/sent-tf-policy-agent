resource "aws_cloudtrail" "validation_test" {
  name                          = "validation-trail"
  s3_bucket_name                = "validation-bucket"
  cloud_watch_logs_group_arn    = "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs:*"
  cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/cloudtrail-cloudwatch-role"
  enable_logging                = true
  is_multi_region_trail         = false
  include_global_service_events = true
}