# IAM.1 - IAM policies should not allow full "*" administrative privileges
#
# This policy checks whether IAM policies (customer managed and inline policies)
# have administrator access by including a statement with "Effect": "Allow",
# "Action": "*", and "Resource": "*".
#
# Control ID: IAM.1
# Source: AWS Security Hub
# Severity: High
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1
#
# Resources checked:
# - aws_iam_policy (customer managed policies)
# - aws_iam_role_policy (inline policies attached to roles)
# - aws_iam_user_policy (inline policies attached to users)
# - aws_iam_group_policy (inline policies attached to groups)

policy {}

# Check customer managed policies (aws_iam_policy)
resource_policy "aws_iam_policy" "no_full_admin_access" {
  locals {
    # Parse the policy document JSON
    policy_doc = core::jsondecode(attrs.policy)
    
    # Check if any statement grants full admin access
    # A statement grants full admin access when ALL of these are true:
    # 1. Effect = "Allow"
    # 2. Action = "*" or ["*"]
    # 3. Resource = "*" or ["*"]
    admin_statements = [
      for statement in core::try(local.policy_doc.Statement, []) :
      statement if (
        core::try(statement.Effect, "") == "Allow" &&
        (
          # Check if Action is "*" (string) or ["*"] (single-element list)
          statement.Action == "*" ||
          (core::try(core::length(statement.Action), -1) == 1 && core::try(statement.Action[0], "") == "*")
        ) &&
        (
          # Check if Resource is "*" (string) or ["*"] (single-element list)
          statement.Resource == "*" ||
          (core::try(core::length(statement.Resource), -1) == 1 && core::try(statement.Resource[0], "") == "*")
        )
      )
    ]
    
    has_admin_access = core::length(local.admin_statements) > 0
  }
  
  enforce {
    condition = !local.has_admin_access
    error_message = "IAM policy contains a statement that grants full administrative privileges (Effect: Allow, Action: *, Resource: *). Remove statements with this combination to follow the principle of least privilege. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
  }
}

# Check inline policies attached to roles (aws_iam_role_policy)
resource_policy "aws_iam_role_policy" "no_full_admin_access" {
  locals {
    # Parse the policy document JSON
    policy_doc = core::jsondecode(attrs.policy)
    
    # Check if any statement grants full admin access
    admin_statements = [
      for statement in core::try(local.policy_doc.Statement, []) :
      statement if (
        core::try(statement.Effect, "") == "Allow" &&
        (
          statement.Action == "*" ||
          (core::try(core::length(statement.Action), -1) == 1 && core::try(statement.Action[0], "") == "*")
        ) &&
        (
          statement.Resource == "*" ||
          (core::try(core::length(statement.Resource), -1) == 1 && core::try(statement.Resource[0], "") == "*")
        )
      )
    ]
    
    has_admin_access = core::length(local.admin_statements) > 0
  }
  
  enforce {
    condition = !local.has_admin_access
    error_message = "IAM role policy contains a statement that grants full administrative privileges (Effect: Allow, Action: *, Resource: *). Remove statements with this combination to follow the principle of least privilege. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
  }
}

# Check inline policies attached to users (aws_iam_user_policy)
resource_policy "aws_iam_user_policy" "no_full_admin_access" {
  locals {
    # Parse the policy document JSON
    policy_doc = core::jsondecode(attrs.policy)
    
    # Check if any statement grants full admin access
    admin_statements = [
      for statement in core::try(local.policy_doc.Statement, []) :
      statement if (
        core::try(statement.Effect, "") == "Allow" &&
        (
          statement.Action == "*" ||
          (core::try(core::length(statement.Action), -1) == 1 && core::try(statement.Action[0], "") == "*")
        ) &&
        (
          statement.Resource == "*" ||
          (core::try(core::length(statement.Resource), -1) == 1 && core::try(statement.Resource[0], "") == "*")
        )
      )
    ]
    
    has_admin_access = core::length(local.admin_statements) > 0
  }
  
  enforce {
    condition = !local.has_admin_access
    error_message = "IAM user policy contains a statement that grants full administrative privileges (Effect: Allow, Action: *, Resource: *). Remove statements with this combination to follow the principle of least privilege. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
  }
}

# Check inline policies attached to groups (aws_iam_group_policy)
resource_policy "aws_iam_group_policy" "no_full_admin_access" {
  locals {
    # Parse the policy document JSON
    policy_doc = core::jsondecode(attrs.policy)
    
    # Check if any statement grants full admin access
    admin_statements = [
      for statement in core::try(local.policy_doc.Statement, []) :
      statement if (
        core::try(statement.Effect, "") == "Allow" &&
        (
          statement.Action == "*" ||
          (core::try(core::length(statement.Action), -1) == 1 && core::try(statement.Action[0], "") == "*")
        ) &&
        (
          statement.Resource == "*" ||
          (core::try(core::length(statement.Resource), -1) == 1 && core::try(statement.Resource[0], "") == "*")
        )
      )
    ]
    
    has_admin_access = core::length(local.admin_statements) > 0
  }
  
  enforce {
    condition = !local.has_admin_access
    error_message = "IAM group policy contains a statement that grants full administrative privileges (Effect: Allow, Action: *, Resource: *). Remove statements with this combination to follow the principle of least privilege. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1 for more details."
  }
}