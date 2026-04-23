# Test cases for RDS Ensure No Default Port Policy

# aws_db_instance passing tests

resource "aws_db_instance" "pass_mysql_non_default_port" {
  attrs = {
    engine = "mysql"
    port = 3307
    identifier = "test-db"
    instance_class = "db.t3.micro"
    allocated_storage = 20
    username = "admin"
  }
}

resource "aws_db_instance" "pass_postgres_non_default_port" {
  attrs = {
    engine = "postgres"
    port = 5433
    identifier = "test-db"
    instance_class = "db.t3.micro"
    allocated_storage = 20
    username = "admin"
  }
}

# aws_db_instance failing tests

resource "aws_db_instance" "fail_mysql_default_port" {
  expect_failure = true
  attrs = {
    engine = "mysql"
    port = 3306
    identifier = "test-db"
    instance_class = "db.t3.micro"
    allocated_storage = 20
    username = "admin"
  }
}

resource "aws_db_instance" "fail_postgres_default_port" {
  expect_failure = true
  attrs = {
    engine = "postgres"
    port = 5432
    identifier = "test-db"
    instance_class = "db.t3.micro"
    allocated_storage = 20
    username = "admin"
  }
}

resource "aws_db_instance" "fail_mysql_no_port" {
  expect_failure = true
  attrs = {
    engine = "mysql"
    identifier = "test-db"
    instance_class = "db.t3.micro"
    allocated_storage = 20
    username = "admin"
  }
}

# aws_rds_cluster passing tests

resource "aws_rds_cluster" "pass_aurora_mysql_non_default_port" {
  attrs = {
    engine = "aurora-mysql"
    port = 3307
    cluster_identifier = "test-cluster"
    master_username = "admin"
  }
}

resource "aws_rds_cluster" "pass_aurora_postgresql_non_default_port" {
  attrs = {
    engine = "aurora-postgresql"
    port = 5433
    cluster_identifier = "test-cluster"
    master_username = "admin"
  }
}

# aws_rds_cluster failing tests

resource "aws_rds_cluster" "fail_aurora_mysql_default_port" {
  expect_failure = true
  attrs = {
    engine = "aurora-mysql"
    port = 3306
    cluster_identifier = "test-cluster"
    master_username = "admin"
  }
}

resource "aws_rds_cluster" "fail_aurora_postgresql_default_port" {
  expect_failure = true
  attrs = {
    engine = "aurora-postgresql"
    port = 5432
    cluster_identifier = "test-cluster"
    master_username = "admin"
  }
}

resource "aws_rds_cluster" "fail_aurora_mysql_no_port" {
  expect_failure = true
  attrs = {
    engine = "aurora-mysql"
    cluster_identifier = "test-cluster"
    master_username = "admin"
  }
}