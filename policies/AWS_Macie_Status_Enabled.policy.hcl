# AWS Macie Status Should Be Enabled
#
# This policy checks if resources of type 'aws_macie2_account' have the 'status'
# attribute set to 'ENABLED' to ensure Amazon Macie is active for the account.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/macie-controls.html#macie-1
#
# Resources checked:
# - aws_macie2_account
#
# Converted from Sentinel policy: aws-macie-status-should-be-enabled

policy {}

resource_policy "aws_macie2_account" "status_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get the status value, defaulting to empty string if not set
        status_value = core::try(attrs.status, "")
        
        # Check if status is ENABLED
        is_enabled = local.status_value == "ENABLED"
    }
    
    enforce {
        condition = local.is_enabled
        error_message = "Attribute 'status' should be 'ENABLED' for AWS Macie Account at '${meta.address}'. Current status: '${local.status_value}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/macie-controls.html#macie-1 for more details."
    }
}