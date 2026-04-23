provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_iam_policy resource
# This validates the policy attribute structure for IAM.1 control
resource "aws_iam_policy" "validation_test" {
  name        = "test-policy"
  description = "Test policy for validation"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Test configuration for aws_iam_role_policy (inline policy)
resource "aws_iam_role" "test_role" {
  name = "test-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "test_inline_policy" {
  name = "test-inline-policy"
  role = aws_iam_role.test_role.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Test configuration for aws_iam_user_policy (inline policy)
resource "aws_iam_user" "test_user" {
  name = "test-user"
}

resource "aws_iam_user_policy" "test_user_policy" {
  name = "test-user-policy"
  user = aws_iam_user.test_user.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Test configuration for aws_iam_group_policy (inline policy)
resource "aws_iam_group" "test_group" {
  name = "test-group"
}

resource "aws_iam_group_policy" "test_group_policy" {
  name  = "test-group-policy"
  group = aws_iam_group.test_group.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}