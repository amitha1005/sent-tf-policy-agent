provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_networkfirewall_firewall
resource "aws_networkfirewall_firewall" "test" {
  name                = "test-firewall"
  firewall_policy_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test"
  vpc_id              = "vpc-12345678"
  
  subnet_mapping {
    subnet_id = "subnet-12345678"
  }
}

# Test configuration for aws_networkfirewall_logging_configuration
resource "aws_networkfirewall_logging_configuration" "test" {
  firewall_arn = aws_networkfirewall_firewall.test.arn
  
  logging_configuration {
    log_destination_config {
      log_destination = {
        bucketName = "test-bucket"
      }
      log_destination_type = "S3"
      log_type            = "FLOW"
    }
  }
}