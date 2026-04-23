provider "aws" {
  region = "us-east-1"
}

resource "aws_ecs_task_definition" "validation_test" {
  family = "test-task"
  
  # Test with host network mode (the focus of the policy)
  network_mode = "host"
  
  # Container definitions with both privileged and user attributes
  container_definitions = jsonencode([
    {
      name      = "test-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      privileged = true
      user      = "nobody"
    }
  ])
  
  # Required for certain launch types
  requires_compatibilities = ["EC2"]
  cpu                      = "256"
  memory                   = "512"
}