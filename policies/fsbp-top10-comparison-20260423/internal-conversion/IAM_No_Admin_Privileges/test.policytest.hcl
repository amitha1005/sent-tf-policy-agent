# Test case 1: PASS - Specific actions (not wildcard)
resource "aws_iam_policy_document" "pass_specific_actions" {
  attrs = {
    statement = [
      {
        effect    = "Allow"
        actions   = ["s3:GetObject"]
        resources = ["arn:aws:s3:::example-bucket/*"]
      }
    ]
  }
}

# Test case 2: PASS - Wildcard actions but specific resources
resource "aws_iam_policy_document" "pass_wildcard_actions_specific_resources" {
  attrs = {
    statement = [
      {
        effect    = "Allow"
        actions   = ["*"]
        resources = ["arn:aws:s3:::example-bucket/*"]
      }
    ]
  }
}

# Test case 3: PASS - Service-specific wildcard actions
resource "aws_iam_policy_document" "pass_service_wildcard_actions" {
  attrs = {
    statement = [
      {
        effect    = "Allow"
        actions   = ["s3:*"]
        resources = ["*"]
      }
    ]
  }
}

# Test case 4: PASS - Deny effect with wildcards
resource "aws_iam_policy_document" "pass_deny_effect" {
  attrs = {
    statement = [
      {
        effect    = "Deny"
        actions   = ["*"]
        resources = ["*"]
      }
    ]
  }
}

# Test case 5: FAIL - Full admin privileges
resource "aws_iam_policy_document" "fail_full_admin_privileges" {
  expect_failure = true
  attrs = {
    statement = [
      {
        effect    = "Allow"
        actions   = ["*"]
        resources = ["*"]
      }
    ]
  }
}

# Test case 6: FAIL - Multiple statements with one granting admin privileges
resource "aws_iam_policy_document" "fail_multiple_statements_one_admin" {
  expect_failure = true
  attrs = {
    statement = [
      {
        effect    = "Allow"
        actions   = ["s3:GetObject"]
        resources = ["arn:aws:s3:::example-bucket/*"]
      },
      {
        effect    = "Allow"
        actions   = ["*"]
        resources = ["*"]
      }
    ]
  }
}

# Test case 7: PASS - Empty statement list
resource "aws_iam_policy_document" "pass_empty_statements" {
  attrs = {
    statement = []
  }
}