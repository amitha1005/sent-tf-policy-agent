resource "aws_athena_workgroup" "validation_test" {
  name = "validation-test-workgroup"

  configuration {
    publish_cloudwatch_metrics_enabled = true
    enforce_workgroup_configuration    = true

    result_configuration {
      output_location = "s3://validation-test-bucket/output/"
    }
  }
}