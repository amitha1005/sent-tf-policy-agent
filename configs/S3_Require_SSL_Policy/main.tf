provider "aws" {
  region = "us-east-1"
}

# Test aws_s3_bucket resource
resource "aws_s3_bucket" "validation_test" {
  bucket = "test-bucket-validation"
}

# Test aws_iam_policy_document data source
data "aws_iam_policy_document" "validation_test" {
  statement {
    effect = "Deny"
    
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    
    actions = ["s3:*"]
    
    resources = [
      "arn:aws:s3:::test-bucket-validation/*",
    ]
    
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# Test aws_s3_bucket_policy resource
resource "aws_s3_bucket_policy" "validation_test" {
  bucket = aws_s3_bucket.validation_test.id
  policy = data.aws_iam_policy_document.validation_test.json
}