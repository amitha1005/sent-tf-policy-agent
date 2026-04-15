# Aurora PostgreSQL DB Clusters Should Publish Logs to CloudWatch Logs
#
# This policy ensures that Amazon Aurora PostgreSQL DB clusters are configured
# to publish logs to Amazon CloudWatch Logs. The policy checks that Aurora 
# PostgreSQL clusters have the "postgresql" log type enabled in their 
# enabled_cloudwatch_logs_exports configuration.
#
# Control: AWS FSBP RDS.37
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-37
#
# Resources checked:
# - aws_rds_cluster (Aurora PostgreSQL clusters only)

policy {}

resource_policy "aws_rds_cluster" "aurora_postgresql_logs_to_cloudwatch" {

  enforcement_level = "advisory"
    # Only evaluate Aurora PostgreSQL clusters
    filter = attrs.engine == "aurora-postgresql"

    locals {
        # Get the enabled CloudWatch logs exports list (default to empty list if not set)
        logs_exports = core::try(attrs.enabled_cloudwatch_logs_exports, [])
        
        # Check if "postgresql" is in the logs exports list
        postgresql_logging_enabled = core::contains(local.logs_exports, "postgresql")
    }

    enforce {
        condition = local.postgresql_logging_enabled
        error_message = "Aurora PostgreSQL DB cluster '${meta.address}' does not publish logs to CloudWatch Logs. The 'enabled_cloudwatch_logs_exports' must include 'postgresql'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-37 for more details."
    }
}