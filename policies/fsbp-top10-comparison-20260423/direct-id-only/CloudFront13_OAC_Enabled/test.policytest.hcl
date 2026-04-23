# Test cases for CloudFront.13 - CloudFront distributions should use origin access control

# PASS: CloudFront distribution with S3 origin that has OAC configured
resource "aws_cloudfront_distribution" "compliant" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "test-bucket.s3.amazonaws.com"
        origin_id                = "test-origin"
        origin_access_control_id = "E2EXAMPLE"
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "test-origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# FAIL: CloudFront distribution with S3 origin without OAC
resource "aws_cloudfront_distribution" "non_compliant" {
  expect_failure = true
  attrs = {
    enabled = true
    origin = [
      {
        domain_name = "test-bucket.s3.amazonaws.com"
        origin_id   = "test-origin"
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "test-origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# FAIL: CloudFront distribution with S3 origin with null OAC
resource "aws_cloudfront_distribution" "null_oac" {
  expect_failure = true
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "test-bucket.s3.amazonaws.com"
        origin_id                = "test-origin"
        origin_access_control_id = null
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "test-origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# FAIL: CloudFront distribution with S3 origin with empty string OAC
resource "aws_cloudfront_distribution" "empty_oac" {
  expect_failure = true
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "test-bucket.s3.amazonaws.com"
        origin_id                = "test-origin"
        origin_access_control_id = ""
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "test-origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# PASS: CloudFront distribution with multiple S3 origins, all with OAC
resource "aws_cloudfront_distribution" "multiple_compliant" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "bucket1.s3.amazonaws.com"
        origin_id                = "origin1"
        origin_access_control_id = "E2EXAMPLE1"
      },
      {
        domain_name              = "bucket2.s3.us-west-2.amazonaws.com"
        origin_id                = "origin2"
        origin_access_control_id = "E2EXAMPLE2"
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "origin1"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# FAIL: CloudFront distribution with multiple S3 origins, one without OAC
resource "aws_cloudfront_distribution" "mixed_compliance" {
  expect_failure = true
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "bucket1.s3.amazonaws.com"
        origin_id                = "origin1"
        origin_access_control_id = "E2EXAMPLE1"
      },
      {
        domain_name = "bucket2.s3.us-west-2.amazonaws.com"
        origin_id   = "origin2"
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "origin1"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# PASS: CloudFront distribution with custom (non-S3) origin
resource "aws_cloudfront_distribution" "custom_origin" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name = "example.com"
        origin_id   = "custom-origin"
        custom_origin_config = {
          http_port              = 80
          https_port             = 443
          origin_protocol_policy = "https-only"
          origin_ssl_protocols   = ["TLSv1.2"]
        }
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "custom-origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}

# PASS: CloudFront distribution with regional S3 endpoint format
resource "aws_cloudfront_distribution" "regional_s3" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "my-bucket.s3.eu-west-1.amazonaws.com"
        origin_id                = "s3-regional"
        origin_access_control_id = "E2EXAMPLE"
      }
    ]
    default_cache_behavior = {
      target_origin_id       = "s3-regional"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD"]
      cached_methods         = ["GET", "HEAD"]
    }
    restrictions = {
      geo_restriction = {
        restriction_type = "none"
      }
    }
    viewer_certificate = {
      cloudfront_default_certificate = true
    }
  }
}