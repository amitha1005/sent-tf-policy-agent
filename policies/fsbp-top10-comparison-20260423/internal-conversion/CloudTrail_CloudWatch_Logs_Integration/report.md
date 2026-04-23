# CloudTrail CloudWatch Logs Group ARN Present Policy

## Policy Metadata

**Policy Name:** cloudtrail-cloudwatch-logs-group-arn-present

**Policy Type:** tfpolicy

**Resource Type:** AWS Security Hub - Foundational Security Best Practices (FSBP)

**Control Reference:** CloudTrail.5 - https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5

**Input Source:** ./input/fsbp/internal/cloudtrail__cloudtrail-cloudwatch-logs-group-arn-present.sentinel

## Summary

This policy ensures that AWS CloudTrail trails have CloudWatch Logs integration configured by requiring the `cloud_watch_logs_group_arn` attribute to be present and non-empty in `aws_cloudtrail` resources.

## Data Collection Method

**Method:** Direct Sentinel policy file analysis

Since the input was a Sentinel policy file (`.sentinel` extension with Sentinel syntax), the policy information was extracted directly from the source file without using search_unified_policy or web search tools.

## Related Terraform Resources

1. **aws_cloudtrail** - Primary resource being validated
   - Main attribute checked: `cloud_watch_logs_group_arn`
   - Related attribute: `cloud_watch_logs_role_arn` (required for CloudWatch integration)

2. **aws_cloudwatch_log_group** - Supporting resource for log storage
   - Provides the ARN referenced in CloudTrail configuration
   - Used to store and manage CloudTrail logs

## Technical Details

The Sentinel policy validates that:
- All `aws_cloudtrail` resources have the `cloud_watch_logs_group_arn` attribute configured
- The attribute value is not empty or false
- The attribute contains a valid constant value (not a variable reference without a value)

## Unclear Points and Resolutions

**No unclear points identified.** 

The policy requirement is straightforward: CloudTrail trails must have CloudWatch Logs integration configured via the `cloud_watch_logs_group_arn` attribute. This aligns with AWS Security Hub's CloudTrail.5 control and AWS best practices for CloudTrail log management and monitoring.

## Resource Validation

### Resources Validated
- Resource Type: `aws_cloudtrail`
- Validation Status: ✅ Success

### Validated Attributes
List all attributes that were successfully validated:
- `cloud_watch_logs_group_arn`: string - The ARN of the CloudWatch Logs log group where CloudTrail logs will be delivered
- `cloud_watch_logs_role_arn`: string - The role ARN for CloudWatch Logs endpoint to assume
- `name`: string (required) - Name of the trail
- `s3_bucket_name`: string (required) - Name of the S3 bucket for log files
- `enable_logging`: bool - Enables logging for the trail
- `is_multi_region_trail`: bool - Whether the trail is multi-region
- `include_global_service_events`: bool - Whether to include global service events

### Terraform Validation Output
```
Success! The configuration is valid.
```

## Policy Generation

### Policy File
- File: ./policy.policy.hcl
- Policy Type: TF Policy
- Policy Name: cloudwatch_logs_group_arn_present

### Policy Code
```hcl
# CloudTrail CloudWatch Logs Group ARN Present Policy
#
# This policy requires resources of type aws_cloudtrail to have
# cloud_watch_logs_group_arn attribute set to a non-empty value.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5
#
# Converted from Sentinel policy
# Policy Name: cloudtrail-cloudwatch-logs-group-arn-present

policy {}

resource_policy "aws_cloudtrail" "cloudwatch_logs_group_arn_present" {
    locals {
        # Get the cloud_watch_logs_group_arn attribute, default to null if not set
        logs_group_arn = core::try(attrs.cloud_watch_logs_group_arn, null)
        
        # Check if the attribute is present and not empty
        has_valid_arn = local.logs_group_arn != null && local.logs_group_arn != ""
    }
    
    enforce {
        condition = local.has_valid_arn
        error_message = "Attribute 'cloud_watch_logs_group_arn' must be present and non-empty for 'aws_cloudtrail' resources. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html#cloudtrail-5 for more details."
    }
}
```

### Implementation Notes
✅ Policy fully implements all requirements

The Sentinel policy checks for the presence of `cloud_watch_logs_group_arn` attribute with a non-empty constant value. The TF Policy implementation:
1. Uses `core::try()` to safely access the attribute with a null default
2. Validates that the attribute is not null AND not an empty string
3. Provides clear error messaging with the security control reference

### Verification Status
- ✓ All requirements verified and implemented
- ✓ Policy correctly checks for attribute presence and non-empty value
- ✓ No limitations identified - policy fully convertible from Sentinel

## Test Case Generation

### Test Files
- GWT Scenarios: ./gwt.json
- Test Cases: ./test.policytest.hcl

### Test Summary
- Total test cases: 4
- Pass scenarios: 1
- Fail scenarios: 3

### Test Scenarios
1. **Pass Test**: CloudTrail with valid cloud_watch_logs_group_arn attribute
2. **Fail Test**: CloudTrail with empty string cloud_watch_logs_group_arn
3. **Fail Test**: CloudTrail without cloud_watch_logs_group_arn attribute
4. **Fail Test**: CloudTrail with null cloud_watch_logs_group_arn

## Test Execution

### Test Command
```
tfpolicy test --policies=.
```

### Test Results
- Status: ✅ Success - All tests passed

### Test Output
```
 # test.policytest.hcl... running
   # resource.aws_cloudtrail.pass_valid_arn... running
   # resource.aws_cloudtrail.pass_valid_arn... pass
   # resource.aws_cloudtrail.fail_empty_string... running
   # resource.aws_cloudtrail.fail_empty_string... pass
   # resource.aws_cloudtrail.fail_missing_attribute... running
   # resource.aws_cloudtrail.fail_missing_attribute... pass
   # resource.aws_cloudtrail.fail_null_value... running
   # resource.aws_cloudtrail.fail_null_value... pass
 # test.policytest.hcl... pass
```

### Summary
✅ **All tests passed successfully**

The policy correctly:
- ✅ Passes when `cloud_watch_logs_group_arn` is present with a valid ARN
- ✅ Fails when `cloud_watch_logs_group_arn` is an empty string
- ✅ Fails when `cloud_watch_logs_group_arn` attribute is missing
- ✅ Fails when `cloud_watch_logs_group_arn` is null

The policy implementation fully meets the requirements and handles all edge cases correctly.