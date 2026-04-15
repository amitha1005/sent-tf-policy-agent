provider "aws" {
  region = "us-east-1"
}

# Test configuration to validate aws_elb resource and listener attributes
resource "aws_elb" "validation_test" {
  name               = "test-elb"
  availability_zones = ["us-east-1a"]

  listener {
    instance_port      = 80
    instance_protocol  = "HTTP"
    lb_port            = 443
    lb_protocol        = "HTTPS"
    ssl_certificate_id = "arn:aws:iam::123456789012:server-certificate/test-cert"
  }

  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "HTTP:80/"
    interval            = 30
  }
}