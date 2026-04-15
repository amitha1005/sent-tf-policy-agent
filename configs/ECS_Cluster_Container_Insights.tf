provider "aws" {
  region = "us-east-1"
}

resource "aws_ecs_cluster" "validation_test" {
  name = "validation-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}