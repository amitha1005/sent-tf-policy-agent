provider "aws" {
  region = "us-east-1"
}

# Test CloudFront distribution with S3 origin
resource "aws_cloudfront_distribution" "validation_test" {
  enabled = true

  origin {
    domain_name              = "mybucket.s3.amazonaws.com"
    origin_id                = "myS3Origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.test.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "myS3Origin"
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
}

# Test CloudFront origin access control
resource "aws_cloudfront_origin_access_control" "test" {
  name                              = "test-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}