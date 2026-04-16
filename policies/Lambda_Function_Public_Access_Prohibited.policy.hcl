# Lambda Function Public Access Prohibited
#
# This policy ensures that AWS Lambda function resource-based policies prohibit
# public access outside of your AWS account. The policy validates that Lambda
# functions do not grant invoke permissions to the public ("*") via the
# aws_lambda_permission resource.
#
# AWS Security Hub Control: Lambda.1
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-1
#
# Resources checked:
# - aws_lambda_permission
#
# Converted from Sentinel Policy: lambda-function-public-access-prohibited

policy {}

resource_policy "aws_lambda_permission" "public_access_prohibited" {

  enforcement_level = "advisory"
    locals {
        # Get the principal value, defaulting to "*" if not set to catch missing configuration
        principal_value = core::try(attrs.principal, "*")
        
        # Check if principal is set to wildcard (public access)
        is_public_access = local.principal_value == "*"
    }
    
    enforce {
        condition = !local.is_public_access
  error_message = "'aws_lambda_function' resource-based policy should prohibit public access outside of your account. The principal field is set to '*' which allows public access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-1 for more details. "
    }
}