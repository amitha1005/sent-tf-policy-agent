// Test cases for Lambda.2 - Lambda functions should use supported runtimes
// Tests cover various scenarios including supported/unsupported runtimes,
// Zip vs Image package types, and edge cases

// Test 1: Pass - Supported Python runtime with Zip package type
resource "aws_lambda_function" "supported_python_zip" {
  attrs = {
    function_name = "test-python-function"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "python3.12"
    package_type  = "Zip"
  }
}

// Test 2: Pass - Supported Node.js runtime with Zip package type
resource "aws_lambda_function" "supported_nodejs_zip" {
  attrs = {
    function_name = "test-nodejs-function"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "nodejs20.x"
    package_type  = "Zip"
  }
}

// Test 3: Pass - Supported Java runtime with Zip package type
resource "aws_lambda_function" "supported_java_zip" {
  attrs = {
    function_name = "test-java-function"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "com.example.Handler"
    runtime       = "java21"
    package_type  = "Zip"
  }
}

// Test 4: Pass - Supported Ruby runtime with default package type (Zip)
resource "aws_lambda_function" "supported_ruby_default" {
  attrs = {
    function_name = "test-ruby-function"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "lambda.handler"
    runtime       = "ruby3.3"
  }
}

// Test 5: Pass - Image package type (skipped by filter)
resource "aws_lambda_function" "image_package_type" {
  attrs = {
    function_name = "test-image-function"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    package_type  = "Image"
    image_uri     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-image:latest"
  }
}

// Test 6: Fail - Unsupported Python runtime (deprecated)
resource "aws_lambda_function" "unsupported_python" {
  expect_failure = true
  attrs = {
    function_name = "test-unsupported-python"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "python3.8"
    package_type  = "Zip"
  }
}

// Test 7: Fail - Unsupported Node.js runtime (deprecated)
resource "aws_lambda_function" "unsupported_nodejs" {
  expect_failure = true
  attrs = {
    function_name = "test-unsupported-nodejs"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "nodejs18.x"
    package_type  = "Zip"
  }
}

// Test 8: Fail - Missing runtime with Zip package type
resource "aws_lambda_function" "missing_runtime_zip" {
  expect_failure = true
  attrs = {
    function_name = "test-missing-runtime"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    package_type  = "Zip"
  }
}

// Test 9: Fail - Empty runtime string with default package type
resource "aws_lambda_function" "empty_runtime_default" {
  expect_failure = true
  attrs = {
    function_name = "test-empty-runtime"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = ""
  }
}