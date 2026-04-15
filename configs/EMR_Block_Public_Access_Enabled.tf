resource "aws_emr_block_public_access_configuration" "validation_test" {
  block_public_security_group_rules = true
  
  permitted_public_security_group_rule_range {
    min_range = 22
    max_range = 22
  }
}