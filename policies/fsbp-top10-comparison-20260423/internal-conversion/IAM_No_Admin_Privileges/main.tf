provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_iam_policy validation
resource "aws_iam_policy" "test_policy" {
  name        = "test-policy"
  description = "Test policy for validation"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::example-bucket/*"]
      }
    ]
  })
}

# Test configuration for aws_iam_policy_document data source validation
data "aws_iam_policy_document" "test_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
}