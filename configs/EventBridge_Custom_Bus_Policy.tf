provider "aws" {
  region = "us-east-1"
}

# Test resource: aws_cloudwatch_event_bus
resource "aws_cloudwatch_event_bus" "test_bus" {
  name        = "test-custom-event-bus"
  description = "Test event bus for validation"
}

# Test resource: aws_cloudwatch_event_bus_policy
resource "aws_cloudwatch_event_bus_policy" "test_policy" {
  event_bus_name = "test-custom-event-bus"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action   = "events:PutEvents"
        Resource = "arn:aws:events:us-east-1:123456789012:event-bus/test-custom-event-bus"
      }
    ]
  })
}