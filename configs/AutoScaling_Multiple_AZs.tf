provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_autoscaling_group validation
resource "aws_autoscaling_group" "validation_test" {
  name                = "validation-test-asg"
  max_size            = 5
  min_size            = 2
  desired_capacity    = 3
  availability_zones  = ["us-east-1a", "us-east-1b"]
  
  # Alternative attribute for VPC-based ASG
  # vpc_zone_identifier = ["subnet-12345678", "subnet-87654321"]
  
  launch_template {
    id      = "lt-12345678"
    version = "$Latest"
  }
  
  health_check_type         = "EC2"
  health_check_grace_period = 300
}