policy "restrict-aws-instance-type" {
  source = "./policies/restrict-aws-instance-type.rego"
  enforcement_level = "mandatory"
}

policy "enforce-required-tags" {
  source = "./policies/enforce-required-tags.rego"
  enforcement_level = "mandatory"
}

policy "restrict-aws-regions" {
  source = "./policies/restrict-aws-regions.rego"
  enforcement_level = "advisory"
}
