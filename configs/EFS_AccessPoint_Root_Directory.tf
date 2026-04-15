provider "aws" {
  region = "us-east-1"
}

resource "aws_efs_file_system" "test" {
  creation_token = "test-efs"
}

resource "aws_efs_access_point" "validation_test" {
  file_system_id = aws_efs_file_system.test.id

  root_directory {
    path = "/test"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "755"
    }
  }

  posix_user {
    gid = 1000
    uid = 1000
  }
}

resource "aws_efs_access_point" "validation_test_root" {
  file_system_id = aws_efs_file_system.test.id

  root_directory {
    path = "/"
  }
}