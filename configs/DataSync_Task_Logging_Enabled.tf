provider "aws" {
  region = "us-east-1"
}

resource "aws_datasync_task" "validation_test" {
  source_location_arn      = "arn:aws:datasync:us-east-1:123456789012:location/loc-12345678901234567"
  destination_location_arn = "arn:aws:datasync:us-east-1:123456789012:location/loc-12345678901234568"
  
  # Attribute being validated for policy
  cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/datasync"
  
  # Options block with log_level attribute
  options {
    log_level = "BASIC"
  }
}