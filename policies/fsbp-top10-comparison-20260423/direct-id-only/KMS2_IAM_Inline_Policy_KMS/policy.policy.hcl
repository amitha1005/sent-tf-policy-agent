# KMS.2 - IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys
#
# This policy enforces that IAM inline policies (user, role, and group policies) do not grant
# kms:Decrypt or kms:ReEncryptFrom actions on all KMS keys (Resource: "*").
#
# Control ID: KMS.2
# Source: AWS Security Hub - NIST 800 53 REV5
# Severity: Medium
# Category: Protect > Secure access management
#
# Resources checked:
# - aws_iam_user_policy (inline policies attached to users)
# - aws_iam_role_policy (inline policies attached to roles)
# - aws_iam_group_policy (inline policies attached to groups)
#
# Related requirements:
# NIST.800-53.r5 AC-2, AC-2(1), AC-3, AC-3(15), AC-3(7), AC-5, AC-6, AC-6(3)
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2

policy {}

resource_policy "aws_iam_user_policy" "kms_decrypt_restriction" {
    locals {
        policy_doc = core::try(core::jsondecode(attrs.policy), null)
        statements = core::try(local.policy_doc.Statement, [])
        blocked_actions = ["kms:Decrypt", "kms:ReEncryptFrom", "kms:*", "kms:Re*", "*"]
        violations = [for stmt in local.statements : stmt if (stmt.Effect == "Allow" && (core::try(stmt.Resource, "") == "*" || core::try(core::contains(core::try(stmt.Resource, []), "*"), false)) && (core::try(core::contains(local.blocked_actions, core::try(stmt.Action, "")), false) || core::try(core::length([for action in core::try(stmt.Action, []) : action if core::contains(local.blocked_actions, action)]) > 0, false)))]
        has_violation = core::length(local.violations) > 0
    }
    
    enforce {
        condition = !local.has_violation
        error_message = "IAM user policy grants kms:Decrypt or kms:ReEncryptFrom actions on all KMS keys (Resource: *). Restrict the Resource element to specific KMS key ARNs."
    }
}

resource_policy "aws_iam_role_policy" "kms_decrypt_restriction" {
    locals {
        policy_doc = core::try(core::jsondecode(attrs.policy), null)
        statements = core::try(local.policy_doc.Statement, [])
        blocked_actions = ["kms:Decrypt", "kms:ReEncryptFrom", "kms:*", "kms:Re*", "*"]
        violations = [for stmt in local.statements : stmt if (stmt.Effect == "Allow" && (core::try(stmt.Resource, "") == "*" || core::try(core::contains(core::try(stmt.Resource, []), "*"), false)) && (core::try(core::contains(local.blocked_actions, core::try(stmt.Action, "")), false) || core::try(core::length([for action in core::try(stmt.Action, []) : action if core::contains(local.blocked_actions, action)]) > 0, false)))]
        has_violation = core::length(local.violations) > 0
    }
    
    enforce {
        condition = !local.has_violation
        error_message = "IAM role policy grants kms:Decrypt or kms:ReEncryptFrom actions on all KMS keys (Resource: *). Restrict the Resource element to specific KMS key ARNs."
    }
}

resource_policy "aws_iam_group_policy" "kms_decrypt_restriction" {
    locals {
        policy_doc = core::try(core::jsondecode(attrs.policy), null)
        statements = core::try(local.policy_doc.Statement, [])
        blocked_actions = ["kms:Decrypt", "kms:ReEncryptFrom", "kms:*", "kms:Re*", "*"]
        violations = [for stmt in local.statements : stmt if (stmt.Effect == "Allow" && (core::try(stmt.Resource, "") == "*" || core::try(core::contains(core::try(stmt.Resource, []), "*"), false)) && (core::try(core::contains(local.blocked_actions, core::try(stmt.Action, "")), false) || core::try(core::length([for action in core::try(stmt.Action, []) : action if core::contains(local.blocked_actions, action)]) > 0, false)))]
        has_violation = core::length(local.violations) > 0
    }
    
    enforce {
        condition = !local.has_violation
        error_message = "IAM group policy grants kms:Decrypt or kms:ReEncryptFrom actions on all KMS keys (Resource: *). Restrict the Resource element to specific KMS key ARNs."
    }
}