# ElastiCache Redis Cluster Auto Backup Enabled Policy
#
# This policy ensures that ElastiCache Redis clusters have automatic backups enabled
# by verifying that the snapshot_retention_limit attribute is greater than 0.
#
# Converted from Sentinel Policy: elasticache-redis-cluster-auto-backup-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html#elasticache-1
#
# Resources checked:
# - aws_elasticache_cluster (excluding read replicas with replication_group_id)
# - aws_elasticache_replication_group

policy {}

# Policy for aws_elasticache_cluster resources
resource_policy "aws_elasticache_cluster" "snapshot_retention" {
  enforcement_level = "advisory"
    locals {
        # Get replication_group_id (safe access for test compatibility)
        replication_group_id = core::try(attrs.replication_group_id, "")
        
        # Skip read replicas - they inherit backup settings from replication group
        is_read_replica = local.replication_group_id != null && local.replication_group_id != ""
        
        # Get snapshot_retention_limit with default of 0 (backups disabled)
        snapshot_retention_limit = core::try(attrs.snapshot_retention_limit, 0)
        
        # Check if backups are enabled (value must be greater than 0)
        backups_enabled = local.snapshot_retention_limit != null && local.snapshot_retention_limit > 0
    }

    # Skip evaluation for read replicas
    filter = !local.is_read_replica

    enforce {
        condition = local.backups_enabled
  error_message = "Attribute 'snapshot_retention_limit' must be greater than 0 for aws_elasticache_cluster resource. Current value: ${local.snapshot_retention_limit}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html#elasticache-1 for more details."
    }
}

# Policy for aws_elasticache_replication_group resources
resource_policy "aws_elasticache_replication_group" "snapshot_retention" {
  enforcement_level = "advisory"
    locals {
        # Get snapshot_retention_limit with default of 0 (backups disabled)
        snapshot_retention_limit = core::try(attrs.snapshot_retention_limit, 0)
        
        # Check if backups are enabled (value must be greater than 0)
        backups_enabled = local.snapshot_retention_limit != null && local.snapshot_retention_limit > 0
    }

    enforce {
        condition = local.backups_enabled
  error_message = "Attribute 'snapshot_retention_limit' must be greater than 0 for aws_elasticache_replication_group resource. Current value: ${local.snapshot_retention_limit}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html#elasticache-1 for more details."
    }
}