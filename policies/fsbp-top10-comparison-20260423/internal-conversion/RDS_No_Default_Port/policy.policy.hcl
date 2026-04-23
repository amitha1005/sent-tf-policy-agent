# RDS Ensure No Default Port Policy
#
# This policy ensures that RDS instances and clusters do not use default ports
# to enhance security by making it harder for attackers to identify database services.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-23
#
# Resources checked:
# - aws_db_instance
# - aws_rds_cluster
#
# Conversion Notes:
# - Converted from Sentinel policy
# - Uses direct attribute access for engine and port validation
# - Implements same default port mapping logic as original Sentinel policy

policy {}

# Default port mappings for various database engines
locals {
  default_ports = {
    "aurora-mysql"          = 3306
    "aurora-postgresql"     = 5432
    "custom-oracle-ee"      = 1521
    "custom-oracle-ee-cdb"  = 1521
    "custom-oracle-se2"     = 1521
    "custom-oracle-se2-cdb" = 1521
    "custom-sqlserver-ee"   = 1433
    "custom-sqlserver-se"   = 1433
    "custom-sqlserver-web"  = 1433
    "db2-ae"                = 50000
    "db2-se"                = 50000
    "mariadb"               = 3306
    "mysql"                 = 3306
    "oracle"                = 1521
    "oracle-ee"             = 1521
    "oracle-ee-cbd"         = 1521
    "oracle-se2"            = 1521
    "oracle-se2-cbd"        = 1521
    "postgres"              = 5432
    "sqlserver"             = 1433
    "sqlserver-ee"          = 1433
    "sqlserver-se"          = 1433
    "sqlserver-ex"          = 1433
    "sqlserver-web"         = 1433
  }
}

resource_policy "aws_db_instance" "no_default_port" {
  locals {
    # Get the engine type for this instance
    engine = core::try(attrs.engine, "")
    
    # Get the configured port (null if not specified)
    configured_port = core::try(attrs.port, null)
    
    # Look up the default port for this engine type
    default_port = core::try(local.default_ports[local.engine], null)
    
    # Determine if port validation applies
    # - Engine must be recognized (default_port exists)
    # - Port must be explicitly configured
    # - Configured port must not match the default
    has_valid_engine = local.default_port != null
    port_is_configured = local.configured_port != null
    port_is_not_default = local.has_valid_engine && local.port_is_configured && local.configured_port != local.default_port
  }
  
  enforce {
    condition = local.port_is_not_default
    error_message = "Attribute 'port' should be defined with non default port value for aws_db_instance resource. Engine '${local.engine}' has default port ${local.default_port}, but configured port is ${local.configured_port}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-23 for more details."
  }
}

resource_policy "aws_rds_cluster" "no_default_port" {
  locals {
    # Get the engine type for this cluster
    engine = core::try(attrs.engine, "")
    
    # Get the configured port (null if not specified)
    configured_port = core::try(attrs.port, null)
    
    # Look up the default port for this engine type
    default_port = core::try(local.default_ports[local.engine], null)
    
    # Determine if port validation applies
    # - Engine must be recognized (default_port exists)
    # - Port must be explicitly configured
    # - Configured port must not match the default
    has_valid_engine = local.default_port != null
    port_is_configured = local.configured_port != null
    port_is_not_default = local.has_valid_engine && local.port_is_configured && local.configured_port != local.default_port
  }
  
  enforce {
    condition = local.port_is_not_default
    error_message = "Attribute 'port' should be defined with non default port value for aws_rds_cluster resource. Engine '${local.engine}' has default port ${local.default_port}, but configured port is ${local.configured_port}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-23 for more details."
  }
}