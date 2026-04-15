provider "aws" {
  region = "us-east-1"
}

# Lambda function for validation testing
resource "aws_lambda_function" "test" {
  function_name = "validation_test_function"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "python3.9"
  filename      = "lambda.zip"
}

# Lambda permission for validation testing
resource "aws_lambda_permission" "validation_test" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.test.function_name
  principal     = "sns.amazonaws.com"
}