# Test cases for KMS.2 - IAM inline policies KMS decrypt restriction

# Test 1: PASS - IAM user policy with kms:Decrypt on specific KMS key
resource "aws_iam_user_policy" "pass_specific_key_arn" {
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\"],\"Resource\":\"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012\"}]}"
  }
}

# Test 2: FAIL - IAM user policy with kms:Decrypt on all KMS keys
resource "aws_iam_user_policy" "fail_decrypt_all_keys" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\"],\"Resource\":\"*\"}]}"
  }
}

# Test 3: FAIL - IAM user policy with kms:ReEncryptFrom on all KMS keys
resource "aws_iam_user_policy" "fail_reencrypt_all_keys" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:ReEncryptFrom\"],\"Resource\":\"*\"}]}"
  }
}

# Test 4: FAIL - IAM user policy with kms:* wildcard on all KMS keys
resource "aws_iam_user_policy" "fail_kms_wildcard_all_keys" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:*\"],\"Resource\":\"*\"}]}"
  }
}

# Test 5: FAIL - IAM user policy with multiple statements, one violating
resource "aws_iam_user_policy" "fail_multiple_statements" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"*\"},{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\"],\"Resource\":\"*\"}]}"
  }
}

# Test 6: PASS - IAM role policy with kms:Decrypt on specific KMS key
resource "aws_iam_role_policy" "pass_specific_key_arn" {
  attrs = {
    name = "test-policy"
    role = "test-role"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\"],\"Resource\":\"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012\"}]}"
  }
}

# Test 7: FAIL - IAM role policy with kms:ReEncryptFrom on all keys
resource "aws_iam_role_policy" "fail_reencrypt_all_keys" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    role = "test-role"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:ReEncryptFrom\"],\"Resource\":\"*\"}]}"
  }
}

# Test 8: PASS - IAM group policy with kms:Decrypt on specific KMS key
resource "aws_iam_group_policy" "pass_specific_key_arn" {
  attrs = {
    name = "test-policy"
    group = "test-group"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\"],\"Resource\":\"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012\"}]}"
  }
}

# Test 9: FAIL - IAM group policy with kms:* on all keys
resource "aws_iam_group_policy" "fail_kms_wildcard_all_keys" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    group = "test-group"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:*\"],\"Resource\":\"*\"}]}"
  }
}

# Test 10: FAIL - IAM user policy with Action array and Resource array containing wildcard
resource "aws_iam_user_policy" "fail_array_format_with_wildcard" {
  expect_failure = true
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\",\"kms:Encrypt\"],\"Resource\":[\"*\"]}]}"
  }
}

# Test 11: PASS - IAM user policy with S3 permissions only (no KMS actions)
resource "aws_iam_user_policy" "pass_no_kms_actions" {
  attrs = {
    name = "test-policy"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\"],\"Resource\":\"*\"}]}"
  }
}

# Test 12: PASS - IAM role policy with kms:Decrypt on specific key with Condition
resource "aws_iam_role_policy" "pass_with_condition_element" {
  attrs = {
    name = "test-policy"
    role = "test-role"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\"],\"Resource\":\"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012\",\"Condition\":{\"StringEquals\":{\"kms:ViaService\":\"s3.us-east-1.amazonaws.com\"}}}]}"
  }
}