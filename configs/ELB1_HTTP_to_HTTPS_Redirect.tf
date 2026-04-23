# Test vpc and subnets for ALB (required dependencies)
resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "test1" {
  vpc_id            = aws_vpc.test.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "test2" {
  vpc_id            = aws_vpc.test.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

# Test Application Load Balancer
resource "aws_lb" "validation_test" {
  name               = "test-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = [aws_subnet.test1.id, aws_subnet.test2.id]
}

# Test HTTP Listener with redirect to HTTPS
resource "aws_lb_listener" "http_validation_test" {
  load_balancer_arn = aws_lb.validation_test.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}