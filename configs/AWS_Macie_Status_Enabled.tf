provider "aws" {
  region = "us-east-1"
}

resource "aws_macie2_account" "validation_test" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}