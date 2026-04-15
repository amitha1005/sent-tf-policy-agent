provider "aws" {
  region = "us-east-1"
}

# Test aws_redshift_cluster resource with legacy logging block
resource "aws_redshift_cluster" "test_with_logging" {
  cluster_identifier = "test-cluster-with-logging"
  node_type         = "dc2.large"
  master_username   = "admin"
  master_password   = "TestPassword123!"
  
  # Legacy logging configuration (if supported)
  # logging {
  #   enable = true
  # }
}

# Test aws_redshift_cluster resource without logging (for validation)
resource "aws_redshift_cluster" "test_without_logging" {
  cluster_identifier = "test-cluster-without-logging"
  node_type         = "dc2.large"
  master_username   = "admin"
  master_password   = "TestPassword123!"
}

# Test aws_redshift_logging resource (modern approach)
resource "aws_redshift_logging" "test_logging" {
  cluster_identifier = aws_redshift_cluster.test_without_logging.cluster_identifier
}