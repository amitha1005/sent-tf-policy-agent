# DynamoDB DAX Cluster Encryption At Rest Enabled
#
# This policy ensures that all AWS DAX (DynamoDB Accelerator) clusters have
# encryption at rest enabled by verifying the server_side_encryption.enabled
# attribute is set to true.
#
# Converted from Sentinel Policy: dynamo-db-accelerator-clusters-encryption-at-rest-enabled
#
# Resources checked:
# - aws_dax_cluster
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html#dynamodb-3

policy {}

resource_policy "aws_dax_cluster" "encryption_at_rest_enabled" {

  enforcement_level = "advisory"
    locals {
        # Safely access server_side_encryption block (may be omitted in tests)
        sse_config = core::try(attrs.server_side_encryption, [])
        
        # Check if server_side_encryption block exists and is configured
        has_sse_config = core::length(local.sse_config) > 0
        
        # Extract the enabled status, defaulting to false if not set
        sse_enabled = local.has_sse_config ? core::try(local.sse_config[0].enabled, false) : false
    }
    
    # Enforce that server_side_encryption must exist and enabled must be true
    enforce {
        condition = local.has_sse_config
  error_message = "Attribute 'server_side_encryption' must be configured for aws_dax_cluster resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html#dynamodb-3 for more details."
    }
    
    enforce {
        condition = local.sse_enabled == true
  error_message = "Attribute 'server_side_encryption' must have 'enabled' set to true for aws_dax_cluster resource. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html#dynamodb-3 for more details."
    }
}