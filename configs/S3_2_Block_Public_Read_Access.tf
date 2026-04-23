# Test resource for S3 bucket
resource "aws_s3_bucket" "validation_test" {
  bucket = "test-bucket-validation"
}

# Test resource for S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "validation_test" {
  bucket = aws_s3_bucket.validation_test.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Test resource for S3 bucket ACL
resource "aws_s3_bucket_acl" "validation_test" {
  bucket = aws_s3_bucket.validation_test.id
  acl    = "private"
}

# Test resource for S3 bucket policy
resource "aws_s3_bucket_policy" "validation_test" {
  bucket = aws_s3_bucket.validation_test.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.validation_test.arn}/*"
      }
    ]
  })
}