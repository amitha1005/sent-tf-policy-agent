# RDS.23 - RDS instances should not use a database engine default port
#
# This policy enforces that RDS database instances and Aurora clusters do not use
# the default port numbers associated with their database engines. Using non-default
# ports helps prevent attackers from easily identifying the database type and reduces
# the attack surface.
#
# Control ID: RDS.23
# Source: AWS Security Hub - NIST 800 53 REV5
# Severity: Low
# Category: Protect > Secure network configuration
#
# Related Requirements: 
# - NIST.800-53.r5 AC-4, AC-4(21), SC-7, SC-7(11), SC-7(16), SC-7(21), SC-7(4), SC-7(5)
#
# Resources checked:
# - aws_db_instance (standalone RDS instances)
# - aws_rds_cluster (Aurora clusters and Multi-AZ DB clusters)
#
# Note: This policy does NOT evaluate aws_rds_cluster_instance resources,
# as they inherit port configuration from their parent cluster.

policy {}

# Policy for standalone RDS DB instances
resource_policy "aws_db_instance" "no_default_port" {
    locals {
        # Map engine types to their default ports
        engine_defaults = {
            "mysql"      = 3306
            "mariadb"    = 3306
            "postgres"   = 5432
            "oracle-se"  = 1521
            "oracle-se1" = 1521
            "oracle-se2" = 1521
            "oracle-ee"  = 1521
            "sqlserver-ex" = 1433
            "sqlserver-web" = 1433
            "sqlserver-se" = 1433
            "sqlserver-ee" = 1433
        }

        # Extract engine name (handle potential null)
        engine = core::try(attrs.engine, "")
        
        # Get the default port for this engine
        default_port = core::try(local.engine_defaults[local.engine], null)
        
        # Get the configured port (null if not specified)
        configured_port = core::try(attrs.port, null)
        
        # Determine if using default port
        # If port is not configured, it will default to engine's default port (FAIL)
        # If port is configured and equals default port (FAIL)
        # If port is configured and differs from default port (PASS)
        uses_default_port = local.configured_port == null || (local.default_port != null && local.configured_port == local.default_port)
    }

    enforce {
        condition = !local.uses_default_port
        error_message = "RDS instance '${meta.address}' must not use the default port for engine '${local.engine}'. Default port: ${local.default_port}. Configured port: ${local.configured_port == null ? "not specified (will default to ${local.default_port})" : local.configured_port}. Please specify a non-default port value. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-23 for more details."
    }
}

# Policy for RDS Aurora clusters
resource_policy "aws_rds_cluster" "no_default_port" {
    locals {
        # Map engine types to their default ports
        engine_defaults = {
            "aurora-mysql"      = 3306
            "aurora-postgresql" = 5432
            "mysql"             = 3306
            "postgres"          = 5432
        }

        # Extract engine name (handle potential null)
        engine = core::try(attrs.engine, "")
        
        # Get the default port for this engine
        default_port = core::try(local.engine_defaults[local.engine], null)
        
        # Get the configured port (null if not specified)
        configured_port = core::try(attrs.port, null)
        
        # Determine if using default port
        # If port is not configured, it will default to engine's default port (FAIL)
        # If port is configured and equals default port (FAIL)
        # If port is configured and differs from default port (PASS)
        uses_default_port = local.configured_port == null || (local.default_port != null && local.configured_port == local.default_port)
    }

    enforce {
        condition = !local.uses_default_port
        error_message = "RDS cluster '${meta.address}' must not use the default port for engine '${local.engine}'. Default port: ${local.default_port}. Configured port: ${local.configured_port == null ? "not specified (will default to ${local.default_port})" : local.configured_port}. Please specify a non-default port value. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-23 for more details."
    }
}