policy "CloudTrail_Log_File_Validation" {
  source            = "./policies-sentinel/CloudTrail_Log_File_Validation.sentinel"
  enforcement_level = "Advisory"
}

policy "S3_Block_Public_Access_Bucket" {
  source            = "./policies-sentinel/S3_Block_Public_Access_Bucket.sentinel"
  enforcement_level = "Advisory"
}

policy "S3_Require_SSL_Policy" {
  source            = "./policies-sentinel/S3_Require_SSL_Policy.sentinel"
  enforcement_level = "Advisory"
}
