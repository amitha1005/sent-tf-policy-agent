provider "aws" {
  region = "us-east-1"
}

# Test configuration for aws_db_instance
resource "aws_db_instance" "validation_test" {
  identifier        = "test-db-instance"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "password123"
  port              = 3307
  skip_final_snapshot = true
}

# Test configuration for aws_rds_cluster
resource "aws_rds_cluster" "validation_test" {
  cluster_identifier  = "test-aurora-cluster"
  engine              = "aurora-mysql"
  engine_version      = "5.7.mysql_aurora.2.10.1"
  master_username     = "admin"
  master_password     = "password123"
  port                = 3307
  skip_final_snapshot = true
}