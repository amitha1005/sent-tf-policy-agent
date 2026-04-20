# Test aws_elasticache_cluster resource
resource "aws_elasticache_cluster" "validation_test" {
  cluster_id           = "test-cluster"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  
  # Attribute to validate: snapshot_retention_limit
  snapshot_retention_limit = 5
  
  # Additional optional attributes mentioned in requirements
  snapshot_window = "05:00-09:00"
  port            = 6379
}

# Test aws_elasticache_replication_group resource
resource "aws_elasticache_replication_group" "validation_test" {
  replication_group_id       = "test-replication-group"
  description                = "Test replication group"
  node_type                  = "cache.t2.micro"
  num_cache_clusters         = 2
  parameter_group_name       = "default.redis7"
  
  # Attribute to validate: snapshot_retention_limit
  snapshot_retention_limit   = 7
  
  # Additional optional attributes mentioned in requirements
  snapshot_window            = "05:00-09:00"
  automatic_failover_enabled = true
  port                       = 6379
  engine                     = "redis"
}
