resource "aws_kinesis_firehose_delivery_stream" "validation_test" {
  name        = "terraform-kinesis-firehose-test-stream"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "AWS_OWNED_CMK"
  }

  extended_s3_configuration {
    role_arn   = "arn:aws:iam::123456789012:role/firehose_test_role"
    bucket_arn = "arn:aws:s3:::test-bucket"
  }
}