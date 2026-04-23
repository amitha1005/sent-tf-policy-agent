provider "aws" {
  region = "us-east-1"
}

# Test aws_iam_policy_document data source (primary target)
data "aws_iam_policy_document" "test_policy" {
  statement {
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    effect    = "Allow"
  }
}

# Test aws_iam_role_policy (inline policy)
resource "aws_iam_role" "test_role" {
  name = "test-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "test_role_policy" {
  name = "test-role-policy"
  role = aws_iam_role.test_role.id
  policy = data.aws_iam_policy_document.test_policy.json
}

# Test aws_iam_user_policy (inline policy)
resource "aws_iam_user" "test_user" {
  name = "test-user"
}

resource "aws_iam_user_policy" "test_user_policy" {
  name   = "test-user-policy"
  user   = aws_iam_user.test_user.name
  policy = data.aws_iam_policy_document.test_policy.json
}

# Test aws_iam_group_policy (inline policy)
resource "aws_iam_group" "test_group" {
  name = "test-group"
}

resource "aws_iam_group_policy" "test_group_policy" {
  name   = "test-group-policy"
  group  = aws_iam_group.test_group.name
  policy = data.aws_iam_policy_document.test_policy.json
}