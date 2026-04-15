# Minimal valid CloudFront distribution for validation
resource "aws_cloudfront_distribution" "validation_test" {
  enabled = true

  origin {
    domain_name = "example.com"
    origin_id   = "example-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "example-origin"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # This is the attribute we need to validate
  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/a1b2c3d4"
}