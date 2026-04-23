# Test cases for S3 Bucket Block Public Read Access Policy

# ============================================================================
# PUBLIC ACCESS BLOCK TESTS
# ============================================================================

# PASS: All four settings enabled
resource "aws_s3_bucket_public_access_block" "all_settings_enabled" {
  attrs = {
    bucket                  = "test-bucket-1"
    block_public_acls       = true
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = true
  }
}

# FAIL: Missing block_public_acls
resource "aws_s3_bucket_public_access_block" "missing_block_public_acls" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-2"
    block_public_acls       = false
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = true
  }
}

# FAIL: Missing ignore_public_acls
resource "aws_s3_bucket_public_access_block" "missing_ignore_public_acls" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-3"
    block_public_acls       = true
    ignore_public_acls      = false
    block_public_policy     = true
    restrict_public_buckets = true
  }
}

# FAIL: Missing block_public_policy
resource "aws_s3_bucket_public_access_block" "missing_block_public_policy" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-4"
    block_public_acls       = true
    ignore_public_acls      = true
    block_public_policy     = false
    restrict_public_buckets = true
  }
}

# FAIL: Missing restrict_public_buckets
resource "aws_s3_bucket_public_access_block" "missing_restrict_public_buckets" {
  expect_failure = true
  attrs = {
    bucket                  = "test-bucket-5"
    block_public_acls       = true
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = false
  }
}

# ============================================================================
# BUCKET ACL TESTS - CANNED ACLs
# ============================================================================

# PASS: Private ACL
resource "aws_s3_bucket_acl" "private_acl" {
  attrs = {
    bucket = "test-bucket-acl-1"
    acl    = "private"
  }
}

# FAIL: public-read ACL
resource "aws_s3_bucket_acl" "public_read_acl" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-2"
    acl    = "public-read"
  }
}

# FAIL: public-read-write ACL
resource "aws_s3_bucket_acl" "public_read_write_acl" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-3"
    acl    = "public-read-write"
  }
}

# FAIL: authenticated-read ACL
resource "aws_s3_bucket_acl" "authenticated_read_acl" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-4"
    acl    = "authenticated-read"
  }
}

# FAIL: aws-exec-read ACL
resource "aws_s3_bucket_acl" "aws_exec_read_acl" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-5"
    acl    = "aws-exec-read"
  }
}

# ============================================================================
# BUCKET ACL TESTS - ACCESS CONTROL POLICY
# ============================================================================

# PASS: WRITE permission (not in prohibited list)
resource "aws_s3_bucket_acl" "acl_with_write_permission" {
  attrs = {
    bucket = "test-bucket-acl-6"
    access_control_policy = [{
      owner = {
        id = "owner-id-1"
      }
      grant = [{
        grantee = {
          type = "CanonicalUser"
          id   = "grantee-id-1"
        }
        permission = "WRITE"
      }]
    }]
  }
}

# FAIL: READ permission
resource "aws_s3_bucket_acl" "acl_with_read_permission" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-7"
    access_control_policy = [{
      owner = {
        id = "owner-id-2"
      }
      grant = [{
        grantee = {
          type = "CanonicalUser"
          id   = "grantee-id-2"
        }
        permission = "READ"
      }]
    }]
  }
}

# FAIL: FULL_CONTROL permission
resource "aws_s3_bucket_acl" "acl_with_full_control_permission" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-8"
    access_control_policy = [{
      owner = {
        id = "owner-id-3"
      }
      grant = [{
        grantee = {
          type = "CanonicalUser"
          id   = "grantee-id-3"
        }
        permission = "FULL_CONTROL"
      }]
    }]
  }
}

# FAIL: READ_ACP permission
resource "aws_s3_bucket_acl" "acl_with_read_acp_permission" {
  expect_failure = true
  attrs = {
    bucket = "test-bucket-acl-9"
    access_control_policy = [{
      owner = {
        id = "owner-id-4"
      }
      grant = [{
        grantee = {
          type = "CanonicalUser"
          id   = "grantee-id-4"
        }
        permission = "READ_ACP"
      }]
    }]
  }
}

# ============================================================================
# BUCKET WITH PUBLIC ACCESS BLOCK TESTS
# ============================================================================

# PASS: Bucket with proper public access block and no ACL violations
resource "aws_s3_bucket" "secure_bucket" {
  attrs = {
    id     = "secure-bucket-1"
    bucket = "secure-bucket-1"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  skip = true
  attrs = {
    bucket                  = "secure-bucket-1"
    block_public_acls       = true
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = true
  }
}

# FAIL: Bucket without proper public access block
resource "aws_s3_bucket" "insecure_bucket" {
  expect_failure = true
  attrs = {
    id     = "insecure-bucket-1"
    bucket = "insecure-bucket-1"
  }
}

resource "aws_s3_bucket_public_access_block" "insecure_bucket_pab" {
  skip = true
  attrs = {
    bucket                  = "insecure-bucket-1"
    block_public_acls       = false
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = true
  }
}

# ============================================================================
# BUCKET POLICY TESTS WITH IAM POLICY DOCUMENTS
# ============================================================================

# PASS: Bucket with policy that doesn't allow public read
resource "aws_s3_bucket" "bucket_with_safe_policy" {
  attrs = {
    id     = "bucket-with-safe-policy"
    bucket = "bucket-with-safe-policy"
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_with_safe_policy_pab" {
  skip = true
  attrs = {
    bucket                  = "bucket-with-safe-policy"
    block_public_acls       = true
    ignore_public_acls      = true
    block_public_policy     = true
    restrict_public_buckets = true
  }
}

data "aws_iam_policy_document" "safe_policy_doc" {
  attrs = {
    json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket-with-safe-policy/*\"}]}"
    statement = [{
      effect = "Allow"
      actions = ["s3:PutObject"]
    }]
  }
}

resource "aws_s3_bucket_policy" "safe_policy" {
  skip = true
  attrs = {
    bucket = "bucket-with-safe-policy"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket-with-safe-policy/*\"}]}"
  }
}

# NOTE: Tests for bucket policy validation with public read actions are not included
# due to documented TF Policy limitations. The policy cannot reliably match bucket
# policies to data sources during resource creation when references are unresolved.
# This is a known limitation documented in the policy file itself.