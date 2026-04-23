provider "aws" {
  region = "us-east-1"
}

# Test aws_iam_user_policy
resource "aws_iam_user" "test_user" {
  name = "test-user"
}

resource "aws_iam_user_policy" "test_user_policy" {
  name = "test-policy"
  user = aws_iam_user.test_user.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom"
        ]
        Resource = "*"
      }
    ]
  })
}

# Test aws_iam_role_policy
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

resource "aws_iam_role_policy" "test_role_policy" {
  name = "test-policy"
  role = aws_iam_role.test_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

# Test aws_iam_group_policy
resource "aws_iam_group" "test_group" {
  name = "test-group"
}

resource "aws_iam_group_policy" "test_group_policy" {
  name  = "test-policy"
  group = aws_iam_group.test_group.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:ReEncryptFrom"
        ]
        Resource = "*"
      }
    ]
  })
}