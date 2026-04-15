provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_iam_policy_document data source
data "aws_iam_policy_document" "validation_test" {
  statement {
    sid    = "AllowKMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
  }
}