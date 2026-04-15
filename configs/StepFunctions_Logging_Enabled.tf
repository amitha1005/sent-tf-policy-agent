provider "aws" {
  region = "us-east-1"
}

resource "aws_sfn_state_machine" "validation_test" {
  name     = "validation-test-state-machine"
  role_arn = "arn:aws:iam::123456789012:role/step-functions-role"
  
  definition = jsonencode({
    Comment = "A Hello World example"
    StartAt = "HelloWorld"
    States = {
      HelloWorld = {
        Type = "Pass"
        Result = "Hello World!"
        End = true
      }
    }
  })

  # The attribute we need to validate for the policy
  logging_configuration {
    level                  = "ALL"
    include_execution_data = true
    log_destination        = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/stepfunctions:*"
  }
}