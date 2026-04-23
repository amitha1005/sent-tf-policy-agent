# Policy Report: Lambda.2 - Lambda functions should use supported runtimes

## Policy Metadata

**Policy Name:** Lambda.2 - Lambda functions should use supported runtimes

**Policy Type:** tfpolicy

**Resource Type:** AWS Security Hub

**Control ID:** Lambda.2

**Compliance Framework:** PCI DSS v4.0.1

**Severity:** Medium

**Category:** Protect > Secure development

## Policy Summary

This policy ensures that AWS Lambda functions use currently supported runtimes and not deprecated versions. Lambda runtimes are built around a combination of operating system, programming language, and software libraries that require regular maintenance and security updates. When a runtime component is no longer supported for security updates, Lambda deprecates the runtime. While deprecated runtimes can still process invocation events, using them poses security risks as they no longer receive critical security patches.

The policy helps organizations maintain secure Lambda functions by enforcing the use of supported runtime versions across all supported languages: .NET, Java, Node.js, Python, and Ruby.

## Data Collection Method

**Primary Tool Used:** search_unified_policy (MCP server: my-python-tools)

**Search Parameters:**
- Query: "Lambda.2"
- Source Filter: "aws_securityhub"
- Search Method: Exact Control ID match

**Result:** Successfully retrieved 1 exact match for Control ID Lambda.2 from AWS Security Hub PCI DSS v4.0.1 compliance framework.

**Reference URL:** https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2

## Related Terraform Resources

The following Terraform resource was identified using terraform-mcp-server (hashicorp/aws provider version 6.42.0):

1. **aws_lambda_function** (Provider Doc ID: 12087491)
   - Primary resource for managing AWS Lambda Functions
   - Key attribute for runtime compliance: `runtime`
   - Related attribute: `package_type` (determines if runtime validation applies)
   - The `runtime` argument is optional but required when `package_type` is "Zip" (the default)

## Supported Runtimes

According to the policy specification, the following runtimes are currently supported:

### .NET Runtimes
- dotnet10
- dotnet8

### Java Runtimes
- java25
- java21
- java17
- java11
- java8.al2

### Node.js Runtimes
- nodejs24.x
- nodejs22.x
- nodejs20.x

### Python Runtimes
- python3.14
- python3.13
- python3.12
- python3.11
- python3.10

### Ruby Runtimes
- ruby3.4
- ruby3.3
- ruby3.2

**Note:** This list represents supported runtimes as defined in the policy specification. AWS regularly updates runtime support, so this list should be maintained to reflect current AWS Lambda runtime availability and deprecation schedules.

## Policy Implementation Notes

**Evaluation Target:**
- Resource type: aws_lambda_function
- Specific focus: Functions with `package_type` of "Zip" (or unspecified, as "Zip" is the default)

**Compliance Check Logic:**
1. Identify all aws_lambda_function resources in the Terraform configuration
2. Check the `package_type` attribute:
   - If `package_type = "Image"`: SKIP evaluation (container-based functions are excluded per Security Hub CSPM behavior)
   - If `package_type = "Zip"` or unspecified: Proceed with runtime validation
3. For Zip package types, verify the `runtime` attribute:
   - Ensure `runtime` is specified (required for Zip package types)
   - Validate that the `runtime` value matches one of the supported runtimes listed in the policy
4. Flag as non-compliant if:
   - Runtime is missing for a Zip-based function
   - Runtime value is not in the supported list
   - Runtime value represents a deprecated version

**Failure Conditions:**
- Lambda function with `package_type = "Zip"` (or unspecified) lacks a `runtime` attribute
- Lambda function uses a runtime that is not in the approved supported list
- Lambda function uses a deprecated or end-of-life runtime version

**Exclusions:**
- Lambda functions with `package_type = "Image"` are explicitly excluded from this control, as container image functions do not use runtime identifiers in the same way

## Unclear Points and Resolutions

**No unclear points identified.**

The policy specification is comprehensive and clear:
- The target resource (Lambda function with Zip package type) is well-defined
- The required configuration (supported runtime values) is explicitly enumerated
- The Terraform provider documentation provides complete details on the `aws_lambda_function` resource
- The AWS Config rule (lambda-function-settings-check) provides additional context
- The exclusion criteria (Image package type) is explicitly stated in the policy description

## Additional Context

**Maintenance Consideration:** The list of supported runtimes evolves over time as AWS adds new runtime versions and deprecates older ones. The policy implementation should be designed to allow easy updates to the supported runtime list without requiring changes to the core policy logic.

**Related AWS Documentation:**
- [Lambda Runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Runtime Deprecation Policy](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtime-support-policy)
- [Runtime Updates](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html)

**Security Rationale:** Using deprecated runtimes exposes Lambda functions to unpatched vulnerabilities. Even though deprecated runtimes continue to function, they no longer receive security updates from AWS, making them potential security risks in production environments.

**Compliance Mapping:**
This control supports multiple compliance frameworks:
- NIST 800-53 Rev. 5: CA-9(1), CM-2, SI-2, SI-2(2), SI-2(4), SI-2(5)
- PCI DSS v4.0.1: Requirement 12.3.4

## Resource Validation

### Resources Validated
- Resource Type: `aws_lambda_function`
- Validation Status: ✅ Success

### Validated Attributes
List of attributes that were successfully validated:
- `function_name`: string - Unique name for the Lambda function
- `role`: string - ARN of the function's execution role
- `handler`: string - Function entry point in code (required for Zip package type)
- `runtime`: string - Identifier of the function's runtime (required for Zip package type)
- `package_type`: string - Lambda deployment package type (valid values: "Zip", "Image")
- `filename`: string - Path to function's deployment package (for Zip package type)
- `image_uri`: string - ECR image URI (for Image package type)

### Terraform Validation Output
```
Success! The configuration is valid.
```

## Policy Generation

### Policy File
- File: ./policy.policy.hcl
- Policy Type: TF Policy
- Policy Name: supported_runtime

### Policy Code (Final - Corrected)
```hcl
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
```

### Implementation Notes
✅ Policy fully implements all requirements from requirement.txt

**Policy Implementation Details:**
1. **Filter Logic**: Uses `filter = core::try(attrs.package_type, "Zip") != "Image"` to skip Image-based Lambda functions as specified in Security Hub CSPM behavior
2. **Runtime Validation**: Implements two-step enforcement:
   - First checks that runtime is specified (not null or empty)
   - Then validates runtime is in the approved list of supported versions
3. **Null Safety**:
   - Uses `core::try(attrs.runtime, "")` to default null values to empty string
   - Uses conditional expression for `is_supported` to avoid passing null to `core::contains()`
   - Second enforce block uses `!local.has_runtime || local.is_supported` to skip validation when runtime is missing (already caught by first enforce)
4. **Error Messages**: Provides clear, actionable messages with links to AWS documentation
5. **Supported Runtimes**: Hardcoded list matches the specification exactly, covering all language families (.NET, Java, Node.js, Python, Ruby)

**Corrections Made:**
- Changed `core::try(attrs.runtime, null)` to `core::try(attrs.runtime, "")` to avoid null in string interpolation
- Changed `is_supported` calculation to use ternary operator to avoid passing null to `core::contains()`
- Changed second enforce condition to `!local.has_runtime || local.is_supported` to avoid evaluation errors when runtime is missing

### Verification Status
- ✓ All requirements verified and implemented
- ✓ Policy handles both Zip and Image package types correctly
- ✓ Runtime validation applies only to Zip-based functions
- ✓ Clear error messages guide remediation
- ✓ No limitations identified - policy fully implements the requirement

## Test Case Generation

### Test Files
- GWT Scenarios: ./gwt.json
- Test Cases: ./test.policytest.hcl

### Test Summary
- Total test cases: 9
- Pass scenarios: 5
  - Supported Python runtime (python3.12) with Zip package type
  - Supported Node.js runtime (nodejs20.x) with Zip package type
  - Supported Java runtime (java21) with Zip package type
  - Supported Ruby runtime (ruby3.3) with default package type
  - Image package type (skipped by filter)
- Fail scenarios: 4
  - Unsupported Python runtime (python3.8)
  - Unsupported Node.js runtime (nodejs18.x)
  - Missing runtime with Zip package type
  - Empty runtime string with default package type

### Test Coverage
The test cases cover:
- ✅ Multiple supported runtimes across different language families (Python, Node.js, Java, Ruby)
- ✅ Unsupported/deprecated runtimes that should fail validation
- ✅ Image package type that should be skipped by the filter
- ✅ Edge cases: missing runtime and empty runtime string
- ✅ Both explicit Zip package type and default (implicit Zip) package type

## Test Execution

### Test Command
```
tfpolicy test --policies=.
```

### Test Results
- Status: ✅ Success
- All 9 test cases passed

### Test Output
```
 # test.policytest.hcl... running
   # resource.aws_lambda_function.supported_python_zip... pass
   # resource.aws_lambda_function.supported_nodejs_zip... pass
   # resource.aws_lambda_function.supported_java_zip... pass
   # resource.aws_lambda_function.supported_ruby_default... pass
   # resource.aws_lambda_function.image_package_type... pass
   # resource.aws_lambda_function.unsupported_python... pass
   # resource.aws_lambda_function.unsupported_nodejs... pass
   # resource.aws_lambda_function.missing_runtime_zip... pass
   # resource.aws_lambda_function.empty_runtime_default... pass
 # test.policytest.hcl... pass
```

### Initial Test Failure and Resolution
**Initial Issue:** The first test run failed on the `missing_runtime_zip` test case with evaluation errors:
- Null value in string interpolation in error message
- Invalid value for `core::contains()` when runtime_value was null

**Root Cause:** The policy used `core::try(attrs.runtime, null)` which caused:
1. Null values to be passed to `core::contains()` function (invalid)
2. Null values in string interpolation within error messages (causes template errors)

**Resolution Applied:**
1. Changed default value from `null` to `""` in `core::try(attrs.runtime, "")`
2. Modified `is_supported` to use conditional expression: `local.has_runtime ? core::contains(...) : false`
3. Changed second enforce condition to `!local.has_runtime || local.is_supported` to properly skip when runtime is missing

**Validation:** After applying the corrections, all 9 test cases passed successfully.

### Final Status
✅ All requirements implemented and validated
✅ All test cases passing
✅ Policy ready for deployment