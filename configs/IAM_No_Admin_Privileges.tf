provider "aws" {
  region = "us-east-1"
}

# Test aws_iam_policy_document data source
data "aws_iam_policy_document" "test_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
}

# Test aws_iam_policy resource with inline policy
resource "aws_iam_policy" "test_inline" {
  name        = "test-inline-policy"
  description = "Test policy with inline JSON"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}

# Test aws_iam_policy resource referencing policy document
resource "aws_iam_policy" "test_reference" {
  name        = "test-reference-policy"
  description = "Test policy referencing data source"
  policy      = data.aws_iam_policy_document.test_policy_document.json
}