provider "aws" {
  region = "us-east-1"
}

resource "aws_glue_job" "validation_test" {
  name     = "test-glue-job"
  role_arn = "arn:aws:iam::123456789012:role/GlueServiceRole"

  command {
    name            = "glueetl"
    script_location = "s3://my-bucket/scripts/test.py"
  }

  glue_version = "3.0"
}