provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudtrail" "validation_test" {
  name                          = "test-trail"
  s3_bucket_name                = "test-bucket"
  enable_log_file_validation    = true
  enable_logging                = true
  is_multi_region_trail         = false
  include_global_service_events = true
}