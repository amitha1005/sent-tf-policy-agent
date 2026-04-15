# LIMITATION:
# This policy has significant limitations compared to the original Sentinel policy.
# The original Sentinel policy checked if aws_iam_policy resources reference 
# aws_iam_policy_document data sources using config.policy.references metadata.
# TF Policy cannot access reference metadata - it only receives resolved attribute values.
# Therefore, this policy can ONLY validate policy document content, but CANNOT enforce
# that aws_iam_policy resources use data source references vs inline JSON.

# IAM No Admin Privileges Policy
#
# Ensures that IAM policy documents do not grant full administrative privileges
# (Effect: Allow, Action: *, Resource: *) to users, roles, or groups.
#
# This policy validates aws_iam_policy_document data sources to ensure they don't
# contain statements that grant unrestricted admin access.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1

policy {}

# Check aws_iam_policy_document data sources for admin privilege violations
resource_policy "aws_iam_policy_document" "no_admin_privileges" {
  enforcement_level = "advisory"
    # Only evaluate policy documents that have statements
    filter = attrs.statement != null && core::length(attrs.statement) > 0

    locals {
        # Find statements that grant admin privileges (Effect: Allow, Actions: *, Resources: *)
        admin_privilege_statements = [
            for statement in attrs.statement :
            statement if (
                core::try(statement.effect, "Allow") == "Allow" &&
                core::contains(core::try(statement.actions, []), "*") &&
                core::contains(core::try(statement.resources, []), "*")
            )
        ]

        has_admin_privileges = core::length(local.admin_privilege_statements) > 0
    }

    enforce {
        condition = !local.has_admin_privileges
        error_message = "IAM policy document '${meta.address}' grants full administrative privileges (Effect: Allow, Action: *, Resource: *). This violates the principle of least privilege. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
    }
}

# Check aws_iam_policy resources for admin privilege violations in inline policies
resource_policy "aws_iam_policy" "no_admin_privileges" {
  enforcement_level = "advisory"
    # Only evaluate policies that have a policy attribute
    filter = attrs.policy != null

    locals {
        # Parse the policy JSON string
        policy_doc = core::try(core::jsondecode(attrs.policy), null)
        
        # Extract statements from the policy document
        statements = core::try(local.policy_doc.Statement, [])
        
        # Find statements that grant admin privileges
        # Need to handle both string and array formats for Action and Resource
        admin_privilege_statements = [
            for statement in local.statements :
            statement if (
                core::try(statement.Effect, "Allow") == "Allow" &&
                (core::try(statement.Action, "") == "*" || core::try(core::contains(statement.Action, "*"), false)) &&
                (core::try(statement.Resource, "") == "*" || core::try(core::contains(statement.Resource, "*"), false))
            )
        ]

        has_admin_privileges = core::length(local.admin_privilege_statements) > 0
    }

    enforce {
        condition = !local.has_admin_privileges
        error_message = "IAM policy '${meta.address}' grants full administrative privileges (Effect: Allow, Action: *, Resource: *). This violates the principle of least privilege. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
    }
}