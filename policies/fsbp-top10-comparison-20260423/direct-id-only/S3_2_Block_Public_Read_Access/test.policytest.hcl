# Test cases for S3.2 - S3 General Purpose Buckets Should Block Public Read Access

# aws_s3_bucket_public_access_block tests

resource "aws_s3_bucket_public_access_block" "pass_all_blocks_enabled" {
  attrs = {
    bucket                  = "test-bucket"
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

resource "aws_s3_bucket_public_access_block" "fail_block_public_acls_false" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-2"
    block_public_acls       = false
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

resource "aws_s3_bucket_public_access_block" "fail_block_public_policy_false" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-3"
    block_public_acls       = true
    block_public_policy     = false
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

resource "aws_s3_bucket_public_access_block" "fail_ignore_public_acls_false" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-4"
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = false
    restrict_public_buckets = true
  }
}

resource "aws_s3_bucket_public_access_block" "fail_restrict_public_buckets_false" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-5"
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = false
  }
}

# aws_s3_bucket_acl tests

resource "aws_s3_bucket_acl" "pass_private_acl" {
  attrs = {
    bucket = "test-bucket"
    acl    = "private"
  }
}

resource "aws_s3_bucket_acl" "fail_public_read_acl" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-2"
    acl    = "public-read"
  }
}

resource "aws_s3_bucket_acl" "fail_public_read_write_acl" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-3"
    acl    = "public-read-write"
  }
}

# aws_s3_bucket_policy tests

resource "aws_s3_bucket_policy" "pass_non_public_policy" {
  attrs = {
    bucket = "test-bucket"
    policy = {
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Principal = {
            AWS = "arn:aws:iam::123456789012:root"
          }
          Action   = "s3:GetObject"
          Resource = "arn:aws:s3:::test-bucket/*"
        }
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "fail_public_get_object" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-2"
    policy = {
      Version = "2012-10-17"
      Statement = [
        {
          Effect    = "Allow"
          Principal = "*"
          Action    = "s3:GetObject"
          Resource  = "arn:aws:s3:::test-bucket-2/*"
        }
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "fail_public_list_bucket" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-3"
    policy = {
      Version = "2012-10-17"
      Statement = [
        {
          Effect    = "Allow"
          Principal = "*"
          Action    = "s3:ListBucket"
          Resource  = "arn:aws:s3:::test-bucket-3"
        }
      ]
    }
  }
}