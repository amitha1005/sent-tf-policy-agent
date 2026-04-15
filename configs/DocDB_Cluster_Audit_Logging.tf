resource "aws_docdb_cluster" "validation_test" {
  cluster_identifier              = "validation-docdb-cluster"
  engine                         = "docdb"
  master_username                = "testuser"
  master_password                = "testpass123"
  backup_retention_period        = 1
  skip_final_snapshot           = true
  enabled_cloudwatch_logs_exports = ["audit"]
}