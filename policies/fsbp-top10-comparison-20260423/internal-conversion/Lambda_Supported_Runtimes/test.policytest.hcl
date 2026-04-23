# Test cases for Lambda Functions Should Use Supported Runtimes policy
# These tests validate that the policy correctly identifies supported and unsupported Lambda runtimes

# Pass Case: Supported Python runtime
resource "aws_lambda_function" "pass_python3_12" {
  attrs = {
    function_name = "test-function-python312"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "python3.12"
  }
}

# Pass Case: Supported Node.js runtime
resource "aws_lambda_function" "pass_nodejs20_x" {
  attrs = {
    function_name = "test-function-nodejs20"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "nodejs20.x"
  }
}

# Pass Case: Supported Java runtime
resource "aws_lambda_function" "pass_java21" {
  attrs = {
    function_name = "test-function-java21"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.Handler::handleRequest"
    runtime       = "java21"
  }
}

# Pass Case: Supported .NET runtime
resource "aws_lambda_function" "pass_dotnet8" {
  attrs = {
    function_name = "test-function-dotnet8"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "Assembly::Namespace.ClassName::MethodName"
    runtime       = "dotnet8"
  }
}

# Pass Case: Supported Ruby runtime
resource "aws_lambda_function" "pass_ruby3_3" {
  attrs = {
    function_name = "test-function-ruby33"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "lambda_function.lambda_handler"
    runtime       = "ruby3.3"
  }
}

# Fail Case: Outdated Python runtime
resource "aws_lambda_function" "fail_python3_8" {
  expect_failure = true
  attrs = {
    function_name = "test-function-python38"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "python3.8"
  }
}

# Fail Case: Outdated Node.js runtime
resource "aws_lambda_function" "fail_nodejs16_x" {
  expect_failure = true
  attrs = {
    function_name = "test-function-nodejs16"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
    runtime       = "nodejs16.x"
  }
}

# Fail Case: Outdated Java runtime
resource "aws_lambda_function" "fail_java8" {
  expect_failure = true
  attrs = {
    function_name = "test-function-java8"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.Handler::handleRequest"
    runtime       = "java8"
  }
}

# Fail Case: Unsupported runtime
resource "aws_lambda_function" "fail_go1_x" {
  expect_failure = true
  attrs = {
    function_name = "test-function-go1x"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "main"
    runtime       = "go1.x"
  }
}

# Fail Case: Missing runtime attribute
resource "aws_lambda_function" "fail_missing_runtime" {
  expect_failure = true
  attrs = {
    function_name = "test-function-no-runtime"
    role          = "arn:aws:iam::123456789012:role/lambda-role"
    handler       = "index.handler"
  }
}