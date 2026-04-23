# Test cases for cloudfront-s3-origin-access-control-enabled policy

# Test 1: PASS - CloudFront distribution with S3 origin and OAC configured
resource "aws_cloudfront_origin_access_control" "test_oac_pass" {
  skip = true
  attrs = {
    id                                = "E1234567890ABC"
    name                              = "test-oac"
    origin_access_control_origin_type = "s3"
    signing_behavior                  = "always"
    signing_protocol                  = "sigv4"
  }
}

resource "aws_cloudfront_distribution" "s3_with_oac_pass" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "mybucket.s3.amazonaws.com"
        origin_id                = "myS3Origin"
        origin_access_control_id = "E1234567890ABC"
      }
    ]
    default_cache_behavior = [
      {
        allowed_methods        = ["GET", "HEAD"]
        cached_methods         = ["GET", "HEAD"]
        target_origin_id       = "myS3Origin"
        viewer_protocol_policy = "redirect-to-https"
        forwarded_values = [
          {
            query_string = false
            cookies = [
              {
                forward = "none"
              }
            ]
          }
        ]
      }
    ]
    restrictions = [
      {
        geo_restriction = [
          {
            restriction_type = "none"
          }
        ]
      }
    ]
    viewer_certificate = [
      {
        cloudfront_default_certificate = true
      }
    ]
  }
}

# Test 2: FAIL - CloudFront distribution with S3 origin but no OAC configured
resource "aws_cloudfront_distribution" "s3_without_oac_fail" {
  expect_failure = true
  attrs = {
    enabled = true
    origin = [
      {
        domain_name = "mybucket.s3.amazonaws.com"
        origin_id   = "myS3Origin"
      }
    ]
    default_cache_behavior = [
      {
        allowed_methods        = ["GET", "HEAD"]
        cached_methods         = ["GET", "HEAD"]
        target_origin_id       = "myS3Origin"
        viewer_protocol_policy = "redirect-to-https"
        forwarded_values = [
          {
            query_string = false
            cookies = [
              {
                forward = "none"
              }
            ]
          }
        ]
      }
    ]
    restrictions = [
      {
        geo_restriction = [
          {
            restriction_type = "none"
          }
        ]
      }
    ]
    viewer_certificate = [
      {
        cloudfront_default_certificate = true
      }
    ]
  }
}

# Test 3: PASS - CloudFront distribution with custom origin (non-S3)
resource "aws_cloudfront_distribution" "custom_origin_pass" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name = "example.com"
        origin_id   = "customOrigin"
        custom_origin_config = [
          {
            http_port              = 80
            https_port             = 443
            origin_protocol_policy = "https-only"
            origin_ssl_protocols   = ["TLSv1.2"]
          }
        ]
      }
    ]
    default_cache_behavior = [
      {
        allowed_methods        = ["GET", "HEAD"]
        cached_methods         = ["GET", "HEAD"]
        target_origin_id       = "customOrigin"
        viewer_protocol_policy = "redirect-to-https"
        forwarded_values = [
          {
            query_string = false
            cookies = [
              {
                forward = "none"
              }
            ]
          }
        ]
      }
    ]
    restrictions = [
      {
        geo_restriction = [
          {
            restriction_type = "none"
          }
        ]
      }
    ]
    viewer_certificate = [
      {
        cloudfront_default_certificate = true
      }
    ]
  }
}

# Test 5: PASS - CloudFront distribution with multiple origins including S3 with OAC
resource "aws_cloudfront_origin_access_control" "test_oac_multi_pass" {
  skip = true
  attrs = {
    id                                = "E2345678901BCD"
    name                              = "test-oac-multi"
    origin_access_control_origin_type = "s3"
    signing_behavior                  = "always"
    signing_protocol                  = "sigv4"
  }
}

resource "aws_cloudfront_distribution" "multi_origin_with_s3_oac_pass" {
  attrs = {
    enabled = true
    origin = [
      {
        domain_name              = "mybucket.s3.amazonaws.com"
        origin_id                = "myS3Origin"
        origin_access_control_id = "E2345678901BCD"
      },
      {
        domain_name = "api.example.com"
        origin_id   = "apiOrigin"
        custom_origin_config = [
          {
            http_port              = 80
            https_port             = 443
            origin_protocol_policy = "https-only"
            origin_ssl_protocols   = ["TLSv1.2"]
          }
        ]
      }
    ]
    default_cache_behavior = [
      {
        allowed_methods        = ["GET", "HEAD"]
        cached_methods         = ["GET", "HEAD"]
        target_origin_id       = "myS3Origin"
        viewer_protocol_policy = "redirect-to-https"
        forwarded_values = [
          {
            query_string = false
            cookies = [
              {
                forward = "none"
              }
            ]
          }
        ]
      }
    ]
    restrictions = [
      {
        geo_restriction = [
          {
            restriction_type = "none"
          }
        ]
      }
    ]
    viewer_certificate = [
      {
        cloudfront_default_certificate = true
      }
    ]
  }
}