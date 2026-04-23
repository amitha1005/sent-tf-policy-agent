# KMS - Restrict IAM Inline Policies from Decrypt All KMS Keys
#
# This policy ensures that IAM policy documents do not allow kms:ReEncryptFrom 
# and kms:Decrypt actions on all KMS keys (Resource: "*"). This aligns with 
# AWS Security Hub control KMS.2.
#
# Resources checked:
# - aws_iam_policy_document (Data Source)
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2

policy {}

resource_policy "aws_iam_policy_document" "kms_restrict_decrypt_all_keys" {
    locals {
        # Get all statements from the policy document
        statements = core::try(attrs.statement, [])
        
        # Find statements with blocked actions
        violations = [
            for statement in local.statements :
            statement if core::contains(core::try(statement.actions, []), "kms:ReEncryptFrom") ||
                        core::contains(core::try(statement.actions, []), "kms:Decrypt")
        ]
        
        # Check if any violations exist
        has_violations = core::length(local.violations) > 0
    }
    
    enforce {
        condition = !local.has_violations
        error_message = "Actions 'kms:ReEncryptFrom' and 'kms:Decrypt' must not be allowed on all 'KMS keys'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2 for more details."
    }
}