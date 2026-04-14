provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudtrail" "validation_test" {
  name                          = "test-trail"
  s3_bucket_name                = "test-bucket"
  enable_log_file_validation    = true
  enable_logging                = true
  is_multi_region_trail         = false
  include_global_service_events = true
}

resource "aws_s3_bucket" "public_access_validation" {
  bucket = "test-bucket-public-access-validation"
}

resource "aws_s3_bucket_public_access_block" "public_access_validation" {
  bucket = aws_s3_bucket.public_access_validation.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "ssl_validation" {
  bucket = "test-bucket-ssl-validation"
}

data "aws_iam_policy_document" "ssl_validation" {
  statement {
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::test-bucket-ssl-validation/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssl_validation" {
  bucket = aws_s3_bucket.ssl_validation.id
  policy = data.aws_iam_policy_document.ssl_validation.json
}
