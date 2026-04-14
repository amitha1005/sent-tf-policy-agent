module "report" {
  source = "./modules/report/report.sentinel"
}

module "tfresources" {
  source = "./modules/tfresources/tfresources.sentinel"
}

module "tfplan-functions" {
  source = "./modules/tfplan-functions/tfplan-functions.sentinel"
}

module "tfconfig-functions" {
  source = "./modules/tfconfig-functions/tfconfig-functions.sentinel"
}

policy "CloudTrail_Log_File_Validation" {
  source            = "./policies-sentinel/CloudTrail_Log_File_Validation.sentinel"
  enforcement_level = "advisory"
}

policy "S3_Block_Public_Access_Bucket" {
  source            = "./policies-sentinel/S3_Block_Public_Access_Bucket.sentinel"
  enforcement_level = "advisory"
}

policy "S3_Require_SSL_Policy" {
  source            = "./policies-sentinel/S3_Require_SSL_Policy.sentinel"
  enforcement_level = "advisory"
}
