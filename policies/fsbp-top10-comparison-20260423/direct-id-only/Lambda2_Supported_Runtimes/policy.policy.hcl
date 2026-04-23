// Lambda.2 - Lambda functions should use supported runtimes
//
// This policy ensures AWS Lambda functions use supported runtimes as specified
// by AWS Security Hub - PCI DSS v4.0.1. Functions with package_type "Image" are
// skipped as per Security Hub CSPM behavior.
//
// Resources checked:
// - aws_lambda_function (Zip package type only)
//
// Compliance: PCI DSS v4.0.1/12.3.4
// Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2

policy {}

resource_policy "aws_lambda_function" "supported_runtime" {
    // Skip Image-based Lambda functions per Security Hub CSPM behavior
    filter = core::try(attrs.package_type, "Zip") != "Image"
    
    locals {
        // List of supported runtimes as of the policy specification
        supported_runtimes = [
            // .NET
            "dotnet10",
            "dotnet8",
            // Java
            "java25",
            "java21",
            "java17",
            "java11",
            "java8.al2",
            // Node.js
            "nodejs24.x",
            "nodejs22.x",
            "nodejs20.x",
            // Python
            "python3.14",
            "python3.13",
            "python3.12",
            "python3.11",
            "python3.10",
            // Ruby
            "ruby3.4",
            "ruby3.3",
            "ruby3.2"
        ]
        
        // Get runtime value, treating null or empty as unsupported
        runtime_value = core::try(attrs.runtime, "")
        
        // Check if runtime is specified
        has_runtime = local.runtime_value != null && local.runtime_value != ""
        
        // Check if runtime is in supported list (only check if has_runtime to avoid null in contains)
        is_supported = local.has_runtime ? core::contains(local.supported_runtimes, local.runtime_value) : false
    }
    
    // Enforce runtime is present for Zip package type
    enforce {
        condition = local.has_runtime
        error_message = "Lambda function '${meta.address}' must specify a runtime when package_type is 'Zip'. For supported runtimes, see https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
    }
    
    // Enforce runtime is supported (only if runtime is present)
    enforce {
        condition = !local.has_runtime || local.is_supported
        error_message = "Lambda function '${meta.address}' uses unsupported runtime '${local.runtime_value}'. Supported runtimes: dotnet10, dotnet8, java25, java21, java17, java11, java8.al2, nodejs24.x, nodejs22.x, nodejs20.x, python3.14, python3.13, python3.12, python3.11, python3.10, ruby3.4, ruby3.3, ruby3.2. For migration guidance, see https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
    }
}