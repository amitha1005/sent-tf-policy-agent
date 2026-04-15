provider "aws" {
  region = "us-east-1"
}

resource "aws_backup_framework" "validation_test" {
  name = "test_framework"

  control {
    name = "BACKUP_RECOVERY_POINT_ENCRYPTED"
  }
}