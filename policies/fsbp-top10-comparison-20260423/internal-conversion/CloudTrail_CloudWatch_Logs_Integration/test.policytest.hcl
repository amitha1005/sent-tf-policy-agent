# Test cases for CloudTrail CloudWatch Logs Group ARN Present Policy

# Test 1: PASS - CloudTrail with valid cloud_watch_logs_group_arn
resource "aws_cloudtrail" "pass_valid_arn" {
  attrs = {
    name                       = "test-trail"
    s3_bucket_name             = "test-bucket"
    cloud_watch_logs_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group:*"
    cloud_watch_logs_role_arn  = "arn:aws:iam::123456789012:role/test-role"
    enable_logging             = true
  }
}

# Test 2: FAIL - CloudTrail with empty string cloud_watch_logs_group_arn
resource "aws_cloudtrail" "fail_empty_string" {
  expect_failure = true
  attrs = {
    name                       = "test-trail"
    s3_bucket_name             = "test-bucket"
    cloud_watch_logs_group_arn = ""
    enable_logging             = true
  }
}

# Test 3: FAIL - CloudTrail without cloud_watch_logs_group_arn attribute
resource "aws_cloudtrail" "fail_missing_attribute" {
  expect_failure = true
  attrs = {
    name           = "test-trail"
    s3_bucket_name = "test-bucket"
    enable_logging = true
  }
}

# Test 4: FAIL - CloudTrail with null cloud_watch_logs_group_arn
resource "aws_cloudtrail" "fail_null_value" {
  expect_failure = true
  attrs = {
    name                       = "test-trail"
    s3_bucket_name             = "test-bucket"
    cloud_watch_logs_group_arn = null
    enable_logging             = true
  }
}