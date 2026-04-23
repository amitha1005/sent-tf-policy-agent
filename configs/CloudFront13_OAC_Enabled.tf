# Validate aws_cloudfront_origin_access_control resource
resource "aws_cloudfront_origin_access_control" "validation_test" {
  name                              = "test-oac"
  description                       = "Test OAC for validation"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Validate aws_cloudfront_distribution resource
resource "aws_cloudfront_distribution" "validation_test" {
  enabled = true

  origin {
    domain_name              = "test-bucket.s3.amazonaws.com"
    origin_id                = "test-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.validation_test.id
  }

  default_cache_behavior {
    target_origin_id       = "test-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

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
}