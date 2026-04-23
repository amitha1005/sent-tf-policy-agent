# Test cases for KMS Restrict IAM Inline Policies policy

# Test 1: PASS - No KMS actions
data "aws_iam_policy_document" "no_kms_actions" {
  attrs = {
    statement = [
      {
        actions = ["s3:GetObject", "s3:PutObject"]
        resources = ["*"]
        effect = "Allow"
      }
    ]
  }
}

# Test 2: PASS - Other KMS actions (not Decrypt or ReEncryptFrom)
data "aws_iam_policy_document" "other_kms_actions" {
  attrs = {
    statement = [
      {
        actions = ["kms:Encrypt", "kms:DescribeKey", "kms:CreateKey"]
        resources = ["*"]
        effect = "Allow"
      }
    ]
  }
}

# Test 3: PASS - Empty statement list
data "aws_iam_policy_document" "empty_statements" {
  attrs = {
    statement = []
  }
}

# Test 4: PASS - No statement attribute at all
data "aws_iam_policy_document" "no_statement_attribute" {
  attrs = {}
}

# Test 5: PASS - Statement with no actions attribute
data "aws_iam_policy_document" "no_actions_attribute" {
  attrs = {
    statement = [
      {
        resources = ["*"]
        effect = "Allow"
      }
    ]
  }
}