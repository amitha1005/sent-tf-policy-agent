resource "aws_codebuild_project" "validation_test" {
  name          = "validation-test-project"
  service_role  = "arn:aws:iam::123456789012:role/codebuild-role"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  source {
    type     = "BITBUCKET"
    location = "https://user:password@bitbucket.org/example/repo.git"
  }
}

# Test with secondary_sources as well
resource "aws_codebuild_project" "validation_test_secondary" {
  name          = "validation-test-secondary"
  service_role  = "arn:aws:iam::123456789012:role/codebuild-role"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  source {
    type     = "CODECOMMIT"
    location = "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/MyRepo"
  }

  secondary_sources {
    type              = "BITBUCKET"
    location          = "https://token:x-token-auth@bitbucket.org/example/secondary.git"
    source_identifier = "secondary"
  }
}