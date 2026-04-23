# Test cases for ECS Task Definition Secure Networking Mode and User Definitions Policy

# PASS: Task definition with host network mode, privileged=true, non-root user
resource "aws_ecs_task_definition" "pass_host_network_privileged_nonroot_user" {
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true,\"user\":\"nginx\"}]"
  }
}

# PASS: Task definition with awsvpc network mode (filtered out)
resource "aws_ecs_task_definition" "pass_awsvpc_network_mode" {
  attrs = {
    family = "test-task"
    network_mode = "awsvpc"
    container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true}]"
  }
}

# FAIL: Task definition with host network mode but privileged=false
resource "aws_ecs_task_definition" "fail_privileged_false" {
  expect_failure = true
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"nginx\"}]"
  }
}

# FAIL: Task definition with host network mode but missing privileged attribute
resource "aws_ecs_task_definition" "fail_missing_privileged" {
  expect_failure = true
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"user\":\"nginx\"}]"
  }
}

# FAIL: Task definition with host network mode but user='root'
resource "aws_ecs_task_definition" "fail_user_root" {
  expect_failure = true
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true,\"user\":\"root\"}]"
  }
}

# FAIL: Task definition with host network mode but missing user attribute
resource "aws_ecs_task_definition" "fail_missing_user" {
  expect_failure = true
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true}]"
  }
}

# FAIL: Multiple containers, one violates privileged requirement
resource "aws_ecs_task_definition" "fail_multiple_containers_privileged" {
  expect_failure = true
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app1\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true,\"user\":\"nginx\"},{\"name\":\"app2\",\"image\":\"redis:latest\",\"cpu\":256,\"memory\":512,\"essential\":false,\"privileged\":false,\"user\":\"redis\"}]"
  }
}

# FAIL: Multiple containers, one violates user requirement
resource "aws_ecs_task_definition" "fail_multiple_containers_user" {
  expect_failure = true
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app1\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true,\"user\":\"nginx\"},{\"name\":\"app2\",\"image\":\"redis:latest\",\"cpu\":256,\"memory\":512,\"essential\":false,\"privileged\":true,\"user\":\"root\"}]"
  }
}

# PASS: Multiple containers all compliant
resource "aws_ecs_task_definition" "pass_multiple_containers_compliant" {
  attrs = {
    family = "test-task"
    network_mode = "host"
    container_definitions = "[{\"name\":\"app1\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true,\"user\":\"nginx\"},{\"name\":\"app2\",\"image\":\"redis:latest\",\"cpu\":256,\"memory\":512,\"essential\":false,\"privileged\":true,\"user\":\"redis\"}]"
  }
}