provider "aws" {
  region = "us-east-1"
}

# Test aws_elasticache_cluster resource
resource "aws_elasticache_cluster" "validation_test" {
  cluster_id           = "test-cluster"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  
  # Attributes to validate for policy
  snapshot_retention_limit = 5
  snapshot_window          = "05:00-09:00"
}

# Test aws_elasticache_cluster with replication_group_id (read replica case)
resource "aws_elasticache_cluster" "validation_test_replica" {
  cluster_id           = "test-replica-cluster"
  replication_group_id = "test-replication-group"
}

# Test aws_elasticache_replication_group resource
resource "aws_elasticache_replication_group" "validation_test" {
  replication_group_id = "test-replication-group"
  description          = "Test replication group"
  node_type            = "cache.t2.micro"
  
  # Attributes to validate for policy
  snapshot_retention_limit = 5
  snapshot_window          = "05:00-09:00"
  engine                   = "redis"
  automatic_failover_enabled = true
  num_cache_clusters       = 2
}