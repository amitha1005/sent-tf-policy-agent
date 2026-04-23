resource "aws_lambda_function" "validation_test" {
  function_name = "test-function"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "lambda.zip"
  
  # Test package_type attribute
  package_type = "Zip"
}

resource "aws_lambda_function" "validation_test_image" {
  function_name = "test-function-image"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  
  # Test Image package_type (should skip validation per requirements)
  package_type = "Image"
  image_uri    = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-image:latest"
}