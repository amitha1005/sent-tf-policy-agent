# KMS - Restrict IAM Inline Policies from Decrypting All KMS Keys
#
# This policy enforces AWS Security Hub control KMS.2, which states that IAM 
# inline policies should not allow decryption and re-encryption actions on all 
# KMS keys. The policy ensures that IAM policy documents do not contain the 
# actions 'kms:Decrypt' or 'kms:ReEncryptFrom' that apply to all KMS keys.
#
# Resources checked:
# - aws_iam_policy_document (data source)
#
# Reference:
# - https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2
#
# Converted from Sentinel Policy:
# - Original policy checked if statement.actions contains "kms:ReEncryptFrom" or "kms:Decrypt"
# - Returns false (violation) when these actions are found

policy {}

resource_policy "aws_iam_policy_document" "restrict_decrypt_all_kms_keys" {

  enforcement_level = "advisory"
    # Only evaluate policy documents that have statement blocks
    filter = attrs.statement != null && core::length(attrs.statement) > 0

    locals {
        # Check all statements for the blocked KMS actions
        statements_with_blocked_actions = [
            for statement in attrs.statement :
            statement if (
                statement.actions != null &&
                (
                    core::contains(statement.actions, "kms:Decrypt") ||
                    core::contains(statement.actions, "kms:ReEncryptFrom")
                )
            )
        ]

        # Policy violates the rule if any statements contain blocked actions
        has_blocked_actions = core::length(local.statements_with_blocked_actions) > 0
    }

    enforce {
        condition = !local.has_blocked_actions
        error_message = "Actions 'kms:ReEncryptFrom' and 'kms:Decrypt' must not be allowed on all 'KMS keys' in IAM policy document '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2 for more details."
    }
}