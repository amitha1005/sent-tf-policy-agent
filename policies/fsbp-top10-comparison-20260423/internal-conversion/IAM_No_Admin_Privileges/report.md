# IAM No Admin Privileges Policy Report

## Policy Metadata

**Policy Name:** IAM No Admin Privileges  
**Policy Type:** tfpolicy  
**Resource Type:** AWS Security Hub (FSBP)  
**Input Source:** ./input/fsbp/internal/iam__iam-no-admin-privileges-allowed-by-policies.sentinel

## Policy Summary

This policy ensures that IAM policies do not grant administrator privileges to users, roles, or groups. It prevents the creation of overly permissive IAM policies that could lead to security risks.

## Data Collection Method

**Source:** Direct Sentinel policy file conversion  
**Method:** The input was a Sentinel policy file (`.sentinel` extension with Sentinel syntax), so no external search tools were used. The policy requirements were extracted directly from the Sentinel code.

## Related Terraform Resources

The following Terraform resources are evaluated by this policy:

1. **aws_iam_policy** (managed resource)
   - Provides an IAM policy
   - Must reference an aws_iam_policy_document data source for the policy attribute

2. **aws_iam_policy_document** (data source)
   - Generates an IAM policy document in JSON format
   - Contains statement blocks that define permissions (actions, resources, effect)

## Policy Rules

The Sentinel policy implements two main rules:

### Rule 1: Check Policy Documents
Examines `aws_iam_policy_document` data sources in the Terraform state to identify statements that grant administrator privileges. A statement is considered to grant admin privileges if it meets ALL of the following conditions:
- Effect: "Allow"
- Actions: contains "*" (wildcard for all actions)
- Resources: contains "*" (wildcard for all resources)

### Rule 2: Check Inline Policies
Examines `aws_iam_policy` managed resources in the Terraform configuration to ensure they reference an `aws_iam_policy_document` data source in their policy attribute. This prevents the use of inline JSON policy strings, which are harder to validate and maintain.

## Unclear Points

**No unclear points identified.**

The Sentinel policy clearly defines:
- What constitutes admin privileges (Effect=Allow, Actions=*, Resources=*)
- Which resources are evaluated (aws_iam_policy and aws_iam_policy_document)
- The validation logic for both checks
- The scope of the policy (only checks these specific resource types, not inline policies in aws_iam_role_policy, aws_iam_user_policy, or aws_iam_group_policy)

## Implementation Notes

The Terraform policy (tfpolicy) should:
1. Iterate through all `aws_iam_policy_document` data sources
2. Check each statement within the policy documents for the admin privilege pattern
3. Iterate through all `aws_iam_policy` resources
4. Verify that each policy references an `aws_iam_policy_document` data source
5. Report violations for any policies that fail either check

## Resource Validation

### Resources Validated
- Resource Type: `aws_iam_policy`
- Resource Type: `aws_iam_policy_document` (data source)
- Validation Status: ✅ Success

### Validated Attributes
**aws_iam_policy:**
- `name`: string - Name of the policy
- `policy`: string - Policy document in JSON format
- `description`: string - Description of the IAM policy

**aws_iam_policy_document (data source):**
- `statement`: block - Configuration block for a policy statement
  - `effect`: string - Whether this statement allows or denies (Allow/Deny)
  - `actions`: list(string) - List of actions
  - `resources`: list(string) - List of resource ARNs

### Terraform Validation Output
```
Success! The configuration is valid.
```

## Policy Generation

### Policy File
- File: ./policy.policy.hcl
- Policy Type: TF Policy
- Policy Name: iam-no-admin-privileges-allowed-by-policies

### Policy Code
```hcl
# LIMITATION: This policy can only partially implement the original Sentinel policy requirements.
#
# The original Sentinel policy has two checks:
# 1. ✅ Check aws_iam_policy_document for admin privilege statements (IMPLEMENTED)
# 2. ❌ Check aws_iam_policy references to aws_iam_policy_document (CANNOT IMPLEMENT)
#
# Reason for limitation #2:
# Terraform Policy does not have access to configuration-level metadata like references.
# We cannot determine if an aws_iam_policy.policy attribute references an
# aws_iam_policy_document data source vs. using an inline JSON string.
# This is a fundamental constraint of TF Policy (see SKILL.md lines 56-65).
#
# What this policy DOES enforce:
# - Validates that aws_iam_policy_document data sources do not contain statements
#   that grant full administrative privileges (Effect=Allow, Actions=*, Resources=*)
#
# What this policy CANNOT enforce:
# - Cannot verify that aws_iam_policy resources use data source references
#   instead of inline JSON policy strings

policy {}

# Check aws_iam_policy_document data sources for admin privilege statements
resource_policy "aws_iam_policy_document" "no_admin_privileges" {
    locals {
        # Get all statements from the policy document
        # Use core::try to handle cases where statement might be null or undefined
        statements = core::try(attrs.statement, [])
        
        # Filter for forbidden statements that grant admin privileges
        # Admin privileges = Effect is "Allow" AND Actions contains "*" AND Resources contains "*"
        forbidden_statements = [
            for statement in local.statements :
            statement if (
                core::try(statement.effect, "Allow") == "Allow" &&
                core::contains(core::try(statement.actions, []), "*") &&
                core::contains(core::try(statement.resources, []), "*")
            )
        ]
        
        has_forbidden_statements = core::length(local.forbidden_statements) > 0
    }
    
    enforce {
        condition = !local.has_forbidden_statements
        error_message = "IAM policies should not allow full '*' administrative privileges. The policy document contains statements with Effect='Allow', Actions=['*'], and Resources=['*']. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
    }
}
```

### Implementation Notes

**Conversion Quality:** Limited

**What was implemented:**
- ✅ Rule 1: Check aws_iam_policy_document data sources for statements that grant full administrative privileges (Effect=Allow, Actions=*, Resources=*)

**What could NOT be implemented:**
- ❌ Rule 2: Verify that aws_iam_policy resources reference aws_iam_policy_document data sources

**Reason for limitation:**
Terraform Policy does not expose configuration-level metadata such as `references` that would allow us to determine whether an `aws_iam_policy.policy` attribute references an `aws_iam_policy_document` data source or contains an inline JSON string. This is a fundamental constraint of TF Policy's evaluation model, which operates on planned values rather than configuration structure.

**Technical details:**
- The original Sentinel policy uses `import "tfconfig/v2"` to access `res.config.policy.references`
- TF Policy only receives attribute values (`attrs.*`), not reference metadata
- This matches the known limitation documented in SKILL.md: "No access to config-level metadata (constant_value, references, expressions)"

### Verification Status
- ✓ All implementable requirements verified and implemented
- ✓ Limitations documented: Cannot verify configuration-level references between aws_iam_policy and aws_iam_policy_document

## Test Case Generation

### Test Files
- GWT Scenarios: ./gwt.json
- Test Cases: ./test.policytest.hcl

### Test Summary
- Total test cases: 7
- Pass scenarios: 4
- Fail scenarios: 2
- Edge case scenarios: 1

### Test Coverage
**Pass scenarios:**
1. Statement with specific actions (not wildcard)
2. Wildcard actions but specific resources
3. Service-specific wildcard actions (e.g., s3:*)
4. Deny effect with wildcards

**Fail scenarios:**
1. Full admin privileges (Effect=Allow, Actions=*, Resources=*)
2. Multiple statements with one granting admin privileges

**Edge cases:**
1. Empty statement list

## Test Execution

### Test Command
```
tfpolicy test --policies=.
```

### Test Results
- Status: ✅ Success
- All tests passed: 7/7

### Test Output
```
 # test.policytest.hcl... running
   # resource.aws_iam_policy_document.pass_specific_actions... running
   # resource.aws_iam_policy_document.pass_specific_actions... pass
   # resource.aws_iam_policy_document.pass_wildcard_actions_specific_resources... running
   # resource.aws_iam_policy_document.pass_wildcard_actions_specific_resources... pass
   # resource.aws_iam_policy_document.pass_service_wildcard_actions... running
   # resource.aws_iam_policy_document.pass_service_wildcard_actions... pass
   # resource.aws_iam_policy_document.pass_deny_effect... running
   # resource.aws_iam_policy_document.pass_deny_effect... pass
   # resource.aws_iam_policy_document.fail_full_admin_privileges... running
   # resource.aws_iam_policy_document.fail_full_admin_privileges... pass
   # resource.aws_iam_policy_document.fail_multiple_statements_one_admin... running
   # resource.aws_iam_policy_document.fail_multiple_statements_one_admin... pass
   # resource.aws_iam_policy_document.pass_empty_statements... running
   # resource.aws_iam_policy_document.pass_empty_statements... pass
 # test.policytest.hcl... pass
```

### Test Analysis
✅ **All test cases passed successfully**

**Passing tests (should pass):**
- ✅ Statement with specific actions (not wildcard) - Passed
- ✅ Wildcard actions but specific resources - Passed
- ✅ Service-specific wildcard actions (s3:*) - Passed
- ✅ Deny effect with wildcards - Passed
- ✅ Empty statement list - Passed

**Failing tests (expected to fail, and did fail):**
- ✅ Full admin privileges (Effect=Allow, Actions=*, Resources=*) - Failed as expected
- ✅ Multiple statements with one granting admin privileges - Failed as expected

### Conclusion
The policy correctly identifies IAM policy documents that grant full administrative privileges and allows all compliant configurations. All 7 test scenarios passed, confirming the policy implementation is correct.