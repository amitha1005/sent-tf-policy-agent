provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_ecr_repository resource validation
# Testing the image_scanning_configuration block and scan_on_push attribute
resource "aws_ecr_repository" "validation_test" {
  name = "test-repository"

  image_scanning_configuration {
    scan_on_push = true
  }
}