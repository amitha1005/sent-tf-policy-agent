provider "aws" {
  region = "us-east-1"
}

# Test aws_db_instance resource
resource "aws_db_instance" "test" {
  identifier           = "test-db"
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "testpassword123"
  port                = 3307
  skip_final_snapshot = true
}

# Test aws_rds_cluster resource
resource "aws_rds_cluster" "test" {
  cluster_identifier  = "test-cluster"
  engine             = "aurora-mysql"
  engine_version     = "8.0.mysql_aurora.3.02.0"
  master_username    = "admin"
  master_password    = "testpassword123"
  port               = 3307
  skip_final_snapshot = true
}