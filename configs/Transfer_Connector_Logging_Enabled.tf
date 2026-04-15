provider "aws" {
  region = "us-east-1"
}

# Validation test for aws_transfer_connector
resource "aws_transfer_connector" "validation_test" {
  access_role = "arn:aws:iam::123456789012:role/transfer-access-role"
  url         = "https://example.com"
  
  # This is the attribute we need to validate - logging_role
  logging_role = "arn:aws:iam::123456789012:role/transfer-logging-role"
  
  as2_config {
    compression          = "ZLIB"
    encryption_algorithm = "AES128_CBC"
    signing_algorithm    = "SHA256"
    mdn_response         = "SYNC"
    
    mdn_signing_algorithm = "SHA256"
    message_subject       = "Transfer message"
    
    local_profile_id  = "p-12345678901234567"
    partner_profile_id = "p-98765432109876543"
  }
}