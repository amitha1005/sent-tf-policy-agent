// Kinesis Firehose Delivery Stream Server-Side Encryption
//
// This policy ensures that all AWS Kinesis Firehose Delivery Stream resources 
// have server-side encryption enabled. The policy validates that the 
// server_side_encryption block exists and has the enabled attribute set to true.
//
// Converted from Sentinel Policy: firehose-server-side-encryption-enabled
//
// AWS Security Hub Control: DataFirehose.1
// Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/datafirehose-controls.html#datafirehose-1
//
// Resources checked:
// - aws_kinesis_firehose_delivery_stream
//
// Conversion Quality: Perfect 1:1 conversion
// The Sentinel policy logic has been fully preserved in Terraform Policy format.

policy {}

resource_policy "aws_kinesis_firehose_delivery_stream" "server_side_encryption_enabled" {

  enforcement_level = "advisory"
    locals {
        // Get the server_side_encryption block (returns empty list if not configured)
        encryption_block = core::try(attrs.server_side_encryption, [])
        
        // Check if the block exists (not empty)
        has_encryption_block = core::length(local.encryption_block) > 0
        
        // Get the enabled value from the first encryption block (default to false)
        encryption_enabled = local.has_encryption_block ? core::try(local.encryption_block[0].enabled, false) : false
    }
    
    // Enforce that the server_side_encryption block exists
    enforce {
        condition = local.has_encryption_block
        error_message = "Attribute 'server_side_encryption' must be configured for 'aws_kinesis_firehose_delivery_stream' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/datafirehose-controls.html#datafirehose-1 for more details."
    }
    
    // Enforce that enabled is set to true within the server_side_encryption block
    enforce {
        condition = local.encryption_enabled == true
        error_message = "Attribute 'server_side_encryption.enabled' must be set to true for 'aws_kinesis_firehose_delivery_stream' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/datafirehose-controls.html#datafirehose-1 for more details."
    }
}