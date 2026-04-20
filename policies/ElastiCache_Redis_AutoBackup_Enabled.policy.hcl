# ElastiCache Redis Cluster Auto Backup Enabled
#
# This policy ensures that automatic backups are enabled for ElastiCache Redis clusters
# by requiring the snapshot_retention_limit attribute to be greater than 0.
#
# Converted from Sentinel policy: elasticache-redis-cluster-auto-backup-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html#elasticache-1
#
# Resources checked:
# - aws_elasticache_cluster (excluding those with replication_group_id)
# - aws_elasticache_replication_group

policy {}

resource_policy "aws_elasticache_cluster" "snapshot_retention" {
    enforcement_level = "advisory"
    # Exclude clusters that are part of a replication group
    # (they inherit snapshot settings from the replication group)
    filter = core::try(attrs.replication_group_id, null) == null || core::try(attrs.replication_group_id, "") == ""

    locals {
        # Get snapshot_retention_limit value, default to 0 if not set
        snapshot_retention_limit = core::try(attrs.snapshot_retention_limit, 0)
    }

    enforce {
        condition = local.snapshot_retention_limit != null && local.snapshot_retention_limit > 0
        error_message = "Attribute 'snapshot_retention_limit' must be greater than 0 for aws_elasticache_cluster resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html#elasticache-1 for more details."
    }
}

resource_policy "aws_elasticache_replication_group" "snapshot_retention" {
    enforcement_level = "advisory"
    locals {
        # Get snapshot_retention_limit value, default to 0 if not set
        snapshot_retention_limit = core::try(attrs.snapshot_retention_limit, 0)
    }

    enforce {
        condition = local.snapshot_retention_limit != null && local.snapshot_retention_limit > 0
        error_message = "Attribute 'snapshot_retention_limit' must be greater than 0 for aws_elasticache_replication_group resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html#elasticache-1 for more details."
    }
}
