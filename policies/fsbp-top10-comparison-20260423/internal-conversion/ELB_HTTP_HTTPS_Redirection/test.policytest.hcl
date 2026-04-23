# Test 1: PASS - ALB with inline HTTP-to-HTTPS redirect
resource "aws_lb" "alb_with_inline_redirect" {
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-1/1234567890abcdef"
    load_balancer_type = "application"
  }
}

resource "aws_lb_listener" "http_listener_inline_redirect" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-1/1234567890abcdef/1234567890abcdef"
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-1/1234567890abcdef"
    port = 80
    protocol = "HTTP"
    default_action = [
      {
        type = "redirect"
        redirect = [
          {
            port = "443"
            protocol = "HTTPS"
            status_code = "HTTP_301"
          }
        ]
      }
    ]
  }
}

# Test 2: FAIL - ALB with HTTP listener without redirect
resource "aws_lb" "alb_without_redirect" {
  expect_failure = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-2/2234567890abcdef"
    load_balancer_type = "application"
  }
}

resource "aws_lb_listener" "http_listener_no_redirect" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-2/2234567890abcdef/2234567890abcdef"
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-2/2234567890abcdef"
    port = 80
    protocol = "HTTP"
    default_action = [
      {
        type = "forward"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/1234567890abcdef"
      }
    ]
  }
}

# Test 3: PASS - ALB with HTTP listener and listener rule redirect
resource "aws_lb" "alb_with_rule_redirect" {
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-3/3234567890abcdef"
    load_balancer_type = "application"
  }
}

resource "aws_lb_listener" "http_listener_for_rule" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-3/3234567890abcdef/3234567890abcdef"
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-3/3234567890abcdef"
    port = 80
    protocol = "HTTP"
    default_action = [
      {
        type = "forward"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/1234567890abcdef"
      }
    ]
  }
}

resource "aws_lb_listener_rule" "redirect_rule" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/test-alb-3/3234567890abcdef/3234567890abcdef/1234567890abcdef"
    listener_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-3/3234567890abcdef/3234567890abcdef"
    priority = 100
    action = [
      {
        type = "redirect"
        redirect = [
          {
            port = "443"
            protocol = "HTTPS"
            status_code = "HTTP_301"
          }
        ]
      }
    ]
  }
}

# Test 4: PASS - Network load balancer (filtered out)
resource "aws_lb" "nlb" {
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/test-nlb/4234567890abcdef"
    load_balancer_type = "network"
  }
}

# Test 5: PASS - ALB with only HTTPS listeners (no HTTP)
resource "aws_lb" "alb_https_only" {
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-5/5234567890abcdef"
    load_balancer_type = "application"
  }
}

resource "aws_lb_listener" "https_listener_only" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-5/5234567890abcdef/5234567890abcdef"
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-5/5234567890abcdef"
    port = 443
    protocol = "HTTPS"
    certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    default_action = [
      {
        type = "forward"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/1234567890abcdef"
      }
    ]
  }
}

# Test 6: FAIL - ALB with HTTP listener redirecting to wrong port
resource "aws_lb" "alb_wrong_port" {
  expect_failure = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-6/6234567890abcdef"
    load_balancer_type = "application"
  }
}

resource "aws_lb_listener" "http_listener_wrong_port" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-6/6234567890abcdef/6234567890abcdef"
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-6/6234567890abcdef"
    port = 80
    protocol = "HTTP"
    default_action = [
      {
        type = "redirect"
        redirect = [
          {
            port = "8443"
            protocol = "HTTPS"
            status_code = "HTTP_301"
          }
        ]
      }
    ]
  }
}

# Test 7: FAIL - ALB with HTTP listener redirecting to wrong protocol
resource "aws_lb" "alb_wrong_protocol" {
  expect_failure = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-7/7234567890abcdef"
    load_balancer_type = "application"
  }
}

resource "aws_lb_listener" "http_listener_wrong_protocol" {
  skip = true
  attrs = {
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb-7/7234567890abcdef/7234567890abcdef"
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb-7/7234567890abcdef"
    port = 80
    protocol = "HTTP"
    default_action = [
      {
        type = "redirect"
        redirect = [
          {
            port = "443"
            protocol = "HTTP"
            status_code = "HTTP_301"
          }
        ]
      }
    ]
  }
}