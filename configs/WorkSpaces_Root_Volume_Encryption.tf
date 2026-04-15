provider "aws" {
  region = "us-east-1"
}

resource "aws_workspaces_workspace" "validation_test" {
  directory_id = "d-926720a732"
  bundle_id    = "wsb-clj85qzj1"
  user_name    = "test.user"
  
  # Key attribute to validate - this is what the policy checks
  root_volume_encryption_enabled = true
  
  tags = {
    Environment = "test"
  }
}