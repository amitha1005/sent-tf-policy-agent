provider "aws" {
  region = "us-east-1"
}

resource "aws_redshiftserverless_namespace" "validation_test" {
  namespace_name = "test-namespace"
  
  # Testing the log_exports attribute mentioned in requirements
  log_exports = ["connectionlog", "userlog"]
}