provider "aws" {
  region = "us-east-1"
}

resource "aws_neptune_cluster" "validation_test" {
  cluster_identifier                  = "test-neptune-cluster"
  engine                             = "neptune"
  backup_retention_period            = 1
  enable_cloudwatch_logs_exports     = ["audit"]
  skip_final_snapshot                = true
}