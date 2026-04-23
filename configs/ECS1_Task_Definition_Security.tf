resource "aws_ecs_task_definition" "validation_test" {
  family = "test-task"
  network_mode = "host"
  
  container_definitions = jsonencode([
    {
      name      = "test-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      privileged = false
      user      = "root"
    }
  ])
}