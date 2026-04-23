# Test cases for IAM.1 - IAM policies should not allow full "*" administrative privileges
# These tests verify that policies correctly identify IAM policies with full admin access

# Test 1: aws_iam_policy - PASS - Specific action (s3:GetObject) and specific resource
resource "aws_iam_policy" "specific_action_specific_resource" {
  attrs = {
    name = "test-specific-action-resource"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}"
  }
}

# Test 2: aws_iam_policy - PASS - Wildcard action but specific resource
resource "aws_iam_policy" "wildcard_action_specific_resource" {
  attrs = {
    name = "test-wildcard-action-specific-resource"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}"
  }
}

# Test 3: aws_iam_policy - FAIL - Full admin access (string format)
resource "aws_iam_policy" "full_admin_string" {
  expect_failure = true
  attrs = {
    name = "test-full-admin-string"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  }
}

# Test 4: aws_iam_policy - FAIL - Full admin access (array format)
resource "aws_iam_policy" "full_admin_array" {
  expect_failure = true
  attrs = {
    name = "test-full-admin-array"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}"
  }
}

# Test 5: aws_iam_role_policy - PASS - Specific service wildcard (ec2:*)
resource "aws_iam_role_policy" "service_wildcard" {
  attrs = {
    name = "test-service-wildcard"
    role = "test-role"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ec2:*\",\"Resource\":\"*\"}]}"
  }
}

# Test 6: aws_iam_role_policy - FAIL - Full admin access
resource "aws_iam_role_policy" "full_admin" {
  expect_failure = true
  attrs = {
    name = "test-full-admin"
    role = "test-role"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  }
}

# Test 7: aws_iam_user_policy - PASS - Deny statement (not Allow)
resource "aws_iam_user_policy" "deny_statement" {
  attrs = {
    name = "test-deny-statement"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  }
}

# Test 8: aws_iam_user_policy - FAIL - Full admin access
resource "aws_iam_user_policy" "full_admin" {
  expect_failure = true
  attrs = {
    name = "test-full-admin"
    user = "test-user"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  }
}

# Test 9: aws_iam_group_policy - PASS - Multiple service wildcards (not full wildcard)
resource "aws_iam_group_policy" "multiple_service_wildcards" {
  attrs = {
    name = "test-multiple-service-wildcards"
    group = "test-group"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\",\"ec2:*\"],\"Resource\":\"*\"}]}"
  }
}

# Test 10: aws_iam_group_policy - FAIL - Full admin access
resource "aws_iam_group_policy" "full_admin" {
  expect_failure = true
  attrs = {
    name = "test-full-admin"
    group = "test-group"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  }
}

# Test 11: aws_iam_policy - FAIL - Multiple statements where one grants full admin
resource "aws_iam_policy" "multiple_statements_one_admin" {
  expect_failure = true
  attrs = {
    name = "test-multiple-statements-one-admin"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"},{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  }
}

# Test 12: aws_iam_policy - PASS - Multiple statements, none grant full admin
resource "aws_iam_policy" "multiple_statements_no_admin" {
  attrs = {
    name = "test-multiple-statements-no-admin"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket1/*\"},{\"Effect\":\"Allow\",\"Action\":\"ec2:DescribeInstances\",\"Resource\":\"*\"}]}"
  }
}