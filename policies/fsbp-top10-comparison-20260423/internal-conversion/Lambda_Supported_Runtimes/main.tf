provider "aws" {
  region = "us-east-1"
}

resource "aws_lambda_function" "validation_test" {
  function_name = "test-function"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "lambda.zip"
}