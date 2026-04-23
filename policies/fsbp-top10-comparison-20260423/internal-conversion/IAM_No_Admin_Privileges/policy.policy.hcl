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