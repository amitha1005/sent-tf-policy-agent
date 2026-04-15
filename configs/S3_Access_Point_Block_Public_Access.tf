provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-for-access-point-validation"
}

resource "aws_s3_access_point" "validation_test" {
  bucket = aws_s3_bucket.test_bucket.id
  name   = "test-access-point"

  public_access_block_configuration {
    block_public_acls       = true
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = true
  }
}