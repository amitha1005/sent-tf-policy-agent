# Test cases for CloudTrail.5 - CloudWatch Logs Integration Policy

# Pass case: CloudTrail with both CloudWatch Logs ARNs configured
resource "aws_cloudtrail" "compliant" {
  attrs = {
    name                          = "compliant-trail"
    s3_bucket_name                = "my-cloudtrail-bucket"
    cloud_watch_logs_group_arn    = "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs:*"
    cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/cloudtrail-cloudwatch-role"
    enable_logging                = true
    is_multi_region_trail         = true
    include_global_service_events = true
  }
}

# Fail case: CloudTrail with only cloud_watch_logs_group_arn (missing role ARN)
resource "aws_cloudtrail" "missing_role" {
  expect_failure = true
  attrs = {
    name                          = "missing-role-trail"
    s3_bucket_name                = "my-cloudtrail-bucket"
    cloud_watch_logs_group_arn    = "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs:*"
    enable_logging                = true
    is_multi_region_trail         = false
    include_global_service_events = true
  }
}

# Fail case: CloudTrail with only cloud_watch_logs_role_arn (missing log group ARN)
resource "aws_cloudtrail" "missing_log_group" {
  expect_failure = true
  attrs = {
    name                          = "missing-log-group-trail"
    s3_bucket_name                = "my-cloudtrail-bucket"
    cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/cloudtrail-cloudwatch-role"
    enable_logging                = true
    is_multi_region_trail         = false
    include_global_service_events = true
  }
}

# Fail case: CloudTrail with neither CloudWatch Logs ARN configured
resource "aws_cloudtrail" "no_cloudwatch" {
  expect_failure = true
  attrs = {
    name                          = "no-cloudwatch-trail"
    s3_bucket_name                = "my-cloudtrail-bucket"
    enable_logging                = true
    is_multi_region_trail         = false
    include_global_service_events = true
  }
}

# Fail case: CloudTrail with empty string cloud_watch_logs_group_arn
resource "aws_cloudtrail" "empty_log_group" {
  expect_failure = true
  attrs = {
    name                          = "empty-log-group-trail"
    s3_bucket_name                = "my-cloudtrail-bucket"
    cloud_watch_logs_group_arn    = ""
    cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/cloudtrail-cloudwatch-role"
    enable_logging                = true
    is_multi_region_trail         = false
    include_global_service_events = true
  }
}

# Fail case: CloudTrail with empty string cloud_watch_logs_role_arn
resource "aws_cloudtrail" "empty_role" {
  expect_failure = true
  attrs = {
    name                          = "empty-role-trail"
    s3_bucket_name                = "my-cloudtrail-bucket"
    cloud_watch_logs_group_arn    = "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs:*"
    cloud_watch_logs_role_arn     = ""
    enable_logging                = true
    is_multi_region_trail         = false
    include_global_service_events = true
  }
}