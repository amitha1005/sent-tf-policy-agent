provider "aws" {
  region = "us-east-1"
}

resource "aws_dax_cluster" "validation_test" {
  cluster_name       = "test-dax-cluster"
  iam_role_arn      = "arn:aws:iam::123456789012:role/DAXServiceRole"
  node_type         = "dax.r4.large"
  replication_factor = 1
  
  server_side_encryption {
    enabled = true
  }
}