# MSK Connect Connector Encryption in Transit Policy
#
# This policy ensures that MSK Connect connectors have encryption in transit enabled
# by checking that the kafka_cluster_encryption_in_transit block is configured with
# encryption_type set to "TLS".
#
# Converted from Sentinel policy: msk-connect-connector-encrypted
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/msk-controls.html#msk-3
#
# Resources checked:
# - aws_mskconnect_connector

policy {}

resource_policy "aws_mskconnect_connector" "encryption_in_transit" {

  enforcement_level = "advisory"
    locals {
        # Safely extract the kafka_cluster_encryption_in_transit block
        encryption_in_transit = core::try(attrs.kafka_cluster_encryption_in_transit, null)
        
        # Check if the block exists and has content (handle null safely)
        has_encryption_config = local.encryption_in_transit != null ? core::length(local.encryption_in_transit) > 0 : false
        
        # Extract encryption_type from the first (and only) block element
        encryption_type = local.has_encryption_config ? core::try(local.encryption_in_transit[0].encryption_type, "") : ""
        
        # Check if encryption type is TLS
        is_encrypted = local.encryption_type == "TLS"
        
        # Safe address for error messages (handle null in test mode)
        resource_address = core::try(meta.address, "unknown")
    }

    enforce {
        condition = local.is_encrypted
        error_message = "MSK Connect connector '${local.resource_address}' must have encryption in transit enabled. Ensure 'kafka_cluster_encryption_in_transit' is configured with 'encryption_type' set to 'TLS'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/msk-controls.html#msk-3 for more details."
    }
}