resource "aws_opensearch_domain" "validation_test" {
  domain_name    = "validation-test-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "t3.small.search"
  }

  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = true
    internal_user_database_enabled = false
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}