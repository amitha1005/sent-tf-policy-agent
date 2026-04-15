resource "aws_rds_cluster" "validation_test" {
  cluster_identifier      = "aurora-cluster-validation"
  engine                  = "aurora-postgresql"
  availability_zones      = ["us-east-1a", "us-east-1b", "us-east-1c"]
  database_name           = "testdb"
  master_username         = "testuser"
  master_password         = "testpassword123"
  backup_retention_period = 5
  enabled_cloudwatch_logs_exports = ["postgresql"]
  skip_final_snapshot     = true
}