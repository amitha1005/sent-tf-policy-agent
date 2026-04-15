# Test configuration for FSx Lustre File System
# Validating: copy_tags_to_backups attribute
resource "aws_fsx_lustre_file_system" "validation_test" {
  storage_capacity = 1200
  subnet_ids       = ["subnet-12345678"]
  deployment_type  = "PERSISTENT_1"
  
  # Attribute to validate
  copy_tags_to_backups = true
  
  tags = {
    Environment = "test"
    Purpose     = "validation"
  }
}