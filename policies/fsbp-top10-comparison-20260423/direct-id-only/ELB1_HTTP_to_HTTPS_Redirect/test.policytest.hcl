# Test cases for ELB.1 - HTTP to HTTPS redirect policy
# Based on AWS Security Hub control for Application Load Balancer listeners

# Pass Case 1: HTTP listener with redirect to HTTPS:443 using HTTP_301
resource "aws_lb_listener" "http_redirect_301" {
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type = "redirect"
      redirect = [{
        protocol    = "HTTPS"
        port        = "443"
        status_code = "HTTP_301"
      }]
    }]
  }
}

# Pass Case 2: HTTP listener with redirect to HTTPS:443 using HTTP_302
resource "aws_lb_listener" "http_redirect_302" {
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type = "redirect"
      redirect = [{
        protocol    = "HTTPS"
        port        = "443"
        status_code = "HTTP_302"
      }]
    }]
  }
}

# Pass Case 3: HTTP listener with redirect using interpolation #{protocol} and #{port}
resource "aws_lb_listener" "http_redirect_interpolated" {
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type = "redirect"
      redirect = [{
        protocol    = "#{protocol}"
        port        = "#{port}"
        status_code = "HTTP_301"
      }]
    }]
  }
}

# Fail Case 1: HTTP listener with forward action (no redirect)
resource "aws_lb_listener" "http_forward_no_redirect" {
  expect_failure = true
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type             = "forward"
      target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890abcdef"
    }]
  }
}

# Fail Case 2: HTTP listener with redirect to HTTP (same protocol, not HTTPS)
resource "aws_lb_listener" "http_redirect_to_http" {
  expect_failure = true
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type = "redirect"
      redirect = [{
        protocol    = "HTTP"
        port        = "80"
        status_code = "HTTP_301"
      }]
    }]
  }
}

# Fail Case 3: HTTP listener with redirect to HTTPS on wrong port (8443 instead of 443)
resource "aws_lb_listener" "http_redirect_wrong_port" {
  expect_failure = true
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type = "redirect"
      redirect = [{
        protocol    = "HTTPS"
        port        = "8443"
        status_code = "HTTP_301"
      }]
    }]
  }
}

# Fail Case 4: HTTP listener with fixed-response action (no redirect)
resource "aws_lb_listener" "http_fixed_response" {
  expect_failure = true
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 80
    protocol          = "HTTP"
    default_action = [{
      type = "fixed-response"
      fixed_response = [{
        content_type = "text/plain"
        message_body = "Access Denied"
        status_code  = "403"
      }]
    }]
  }
}

# Filter Test 1: HTTPS listener on port 443 (should not be evaluated by policy)
resource "aws_lb_listener" "https_listener" {
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 443
    protocol          = "HTTPS"
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    default_action = [{
      type             = "forward"
      target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890abcdef"
    }]
  }
}

# Filter Test 2: HTTP listener on port 8080 (should not be evaluated by policy)
resource "aws_lb_listener" "http_8080" {
  attrs = {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef"
    port              = 8080
    protocol          = "HTTP"
    default_action = [{
      type             = "forward"
      target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890abcdef"
    }]
  }
}