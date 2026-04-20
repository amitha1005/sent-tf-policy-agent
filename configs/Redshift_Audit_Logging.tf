provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_redshift_cluster
resource "aws_redshift_cluster" "validation_test" {
  cluster_identifier = "test-cluster"
  node_type         = "dc2.large"
  master_username   = "testuser"
  master_password   = "TestPassword123!"
  
  # Optional but commonly used attributes
  database_name     = "testdb"
  cluster_type      = "single-node"
  
  # Skip snapshot identifier to avoid complications
  skip_final_snapshot = true
}

# Test configuration for aws_redshift_logging
resource "aws_redshift_logging" "validation_test" {
  cluster_identifier   = aws_redshift_cluster.validation_test.cluster_identifier
  log_destination_type = "s3"
  bucket_name         = "test-bucket"
  s3_key_prefix       = "logs/"
}
