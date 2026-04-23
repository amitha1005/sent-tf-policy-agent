provider "aws" {
  region = "us-east-1"
}

# Test aws_s3_bucket resource
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-validation-bucket"
}

# Test aws_s3_bucket_public_access_block resource
resource "aws_s3_bucket_public_access_block" "test_pab" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Test aws_s3_bucket_policy resource
resource "aws_s3_bucket_policy" "test_policy" {
  bucket = aws_s3_bucket.test_bucket.id
  policy = data.aws_iam_policy_document.test_doc.json
}

# Test aws_iam_policy_document data source
data "aws_iam_policy_document" "test_doc" {
  statement {
    sid    = "TestStatement"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
    ]

    resources = [
      "${aws_s3_bucket.test_bucket.arn}/*",
    ]
  }
}

# Test aws_s3_bucket_acl resource
resource "aws_s3_bucket_acl" "test_acl" {
  bucket = aws_s3_bucket.test_bucket.id
  acl    = "private"
}

# Test aws_s3_bucket_acl with access_control_policy
resource "aws_s3_bucket_acl" "test_acl_policy" {
  bucket = aws_s3_bucket.test_bucket.id

  access_control_policy {
    owner {
      id = "test-owner-id"
    }

    grant {
      grantee {
        type = "CanonicalUser"
        id   = "test-grantee-id"
      }
      permission = "READ"
    }
  }
}