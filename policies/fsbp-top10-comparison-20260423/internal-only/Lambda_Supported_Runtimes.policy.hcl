# Lambda Functions Should Use Supported Runtimes
#
# This policy ensures that AWS Lambda functions use only supported runtime versions.
# It validates that the 'runtime' attribute of 'aws_lambda_function' resources matches
# one of the currently supported runtime values for each programming language.
#
# Control ID: Lambda.2 (AWS Security Hub - Foundational Security Best Practices)
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2
#
# Supported Runtimes:
# - Node.js: nodejs22.x, nodejs20.x, nodejs18.x
# - Python: python3.13, python3.12, python3.11, python3.10, python3.9
# - Java: java21, java17, java11, java8.al2
# - .NET: dotnet8
# - Ruby: ruby3.3, ruby3.2

policy {}

resource_policy "aws_lambda_function" "supported_runtimes" {
    locals {
        # List of supported runtime values
        supported_runtimes = [
            "dotnet8",
            "java21",
            "java17",
            "java11",
            "java8.al2",
            "nodejs22.x",
            "nodejs20.x",
            "nodejs18.x",
            "python3.13",
            "python3.12",
            "python3.11",
            "python3.10",
            "python3.9",
            "ruby3.3",
            "ruby3.2"
        ]

        # Get runtime value, default to empty string if not set
        runtime_value = core::try(attrs.runtime, "")

        # Check if runtime is in the supported list
        is_supported_runtime = core::contains(local.supported_runtimes, local.runtime_value)
    }

    enforce {
        condition = local.is_supported_runtime
        error_message = "'aws_lambda_function' runtime settings should match the expected values set for the supported runtimes in each language. Current runtime: '${local.runtime_value}'. Supported runtimes: dotnet8, java21, java17, java11, java8.al2, nodejs22.x, nodejs20.x, nodejs18.x, python3.13, python3.12, python3.11, python3.10, python3.9, ruby3.3, ruby3.2. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2 for more details."
    }
}