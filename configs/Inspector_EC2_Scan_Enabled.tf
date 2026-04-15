provider "aws" {
  region = "us-east-1"
}

resource "aws_inspector2_enabler" "validation_test" {
  account_ids    = ["123456789012"]
  resource_types = ["EC2"]
}