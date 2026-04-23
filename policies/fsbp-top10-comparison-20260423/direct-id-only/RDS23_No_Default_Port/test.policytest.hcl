# Test cases for RDS.23 - RDS instances should not use a database engine default port

# ========== aws_db_instance tests ==========

# PASS: MySQL with non-default port
resource "aws_db_instance" "pass_mysql_non_default_port" {
  attrs = {
    engine = "mysql"
    port   = 3307
  }
}

# FAIL: MySQL with default port
resource "aws_db_instance" "fail_mysql_default_port" {
  expect_failure = true
  attrs = {
    engine = "mysql"
    port   = 3306
  }
}

# FAIL: MySQL with no port specified
resource "aws_db_instance" "fail_mysql_no_port" {
  expect_failure = true
  attrs = {
    engine = "mysql"
  }
}

# PASS: PostgreSQL with non-default port
resource "aws_db_instance" "pass_postgres_non_default_port" {
  attrs = {
    engine = "postgres"
    port   = 5433
  }
}

# FAIL: PostgreSQL with default port
resource "aws_db_instance" "fail_postgres_default_port" {
  expect_failure = true
  attrs = {
    engine = "postgres"
    port   = 5432
  }
}

# PASS: Oracle with non-default port
resource "aws_db_instance" "pass_oracle_non_default_port" {
  attrs = {
    engine = "oracle-se2"
    port   = 1522
  }
}

# FAIL: Oracle with default port
resource "aws_db_instance" "fail_oracle_default_port" {
  expect_failure = true
  attrs = {
    engine = "oracle-se2"
    port   = 1521
  }
}

# PASS: SQL Server with non-default port
resource "aws_db_instance" "pass_sqlserver_non_default_port" {
  attrs = {
    engine = "sqlserver-ex"
    port   = 1434
  }
}

# FAIL: SQL Server with default port
resource "aws_db_instance" "fail_sqlserver_default_port" {
  expect_failure = true
  attrs = {
    engine = "sqlserver-ex"
    port   = 1433
  }
}

# ========== aws_rds_cluster tests ==========

# PASS: Aurora MySQL with non-default port
resource "aws_rds_cluster" "pass_aurora_mysql_non_default_port" {
  attrs = {
    engine = "aurora-mysql"
    port   = 3307
  }
}

# FAIL: Aurora MySQL with default port
resource "aws_rds_cluster" "fail_aurora_mysql_default_port" {
  expect_failure = true
  attrs = {
    engine = "aurora-mysql"
    port   = 3306
  }
}

# FAIL: Aurora MySQL with no port specified
resource "aws_rds_cluster" "fail_aurora_mysql_no_port" {
  expect_failure = true
  attrs = {
    engine = "aurora-mysql"
  }
}

# PASS: Aurora PostgreSQL with non-default port
resource "aws_rds_cluster" "pass_aurora_postgres_non_default_port" {
  attrs = {
    engine = "aurora-postgresql"
    port   = 5433
  }
}

# FAIL: Aurora PostgreSQL with default port
resource "aws_rds_cluster" "fail_aurora_postgres_default_port" {
  expect_failure = true
  attrs = {
    engine = "aurora-postgresql"
    port   = 5432
  }
}