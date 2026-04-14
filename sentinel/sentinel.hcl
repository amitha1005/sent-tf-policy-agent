policy "restrict-aws-instance-type" {
  source = "./policies/restrict-aws-instance-type.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "enforce-required-tags" {
  source = "./policies/enforce-required-tags.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "restrict-aws-regions" {
  source = "./policies/restrict-aws-regions.sentinel"
  enforcement_level = "soft-mandatory"
}
