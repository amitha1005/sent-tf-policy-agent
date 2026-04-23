# Test cases for ECS.1 - Amazon ECS Task Definitions Secure Networking and User Configuration

# PASS: Non-host network mode (awsvpc)
resource "aws_ecs_task_definition" "pass_awsvpc_network_mode" {
  attrs = {
    family = "test-task-awsvpc"
    network_mode = "awsvpc"
    container_definitions = "[{\"name\":\"test-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"root\"}]"
  }
}

# PASS: Non-host network mode (bridge)
resource "aws_ecs_task_definition" "pass_bridge_network_mode" {
  attrs = {
    family = "test-task-bridge"
    network_mode = "bridge"
    container_definitions = "[{\"name\":\"test-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true}]"
  }
}

# PASS: Host mode with privileged=true
resource "aws_ecs_task_definition" "pass_host_mode_with_privileged" {
  attrs = {
    family = "test-task-privileged"
    network_mode = "host"
    container_definitions = "[{\"name\":\"privileged-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true}]"
  }
}

# PASS: Host mode with non-root user (string username)
resource "aws_ecs_task_definition" "pass_host_mode_with_nonroot_user" {
  attrs = {
    family = "test-task-nonroot"
    network_mode = "host"
    container_definitions = "[{\"name\":\"appuser-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"appuser\"}]"
  }
}

# PASS: Host mode with numeric UID
resource "aws_ecs_task_definition" "pass_host_mode_with_numeric_uid" {
  attrs = {
    family = "test-task-numericuid"
    network_mode = "host"
    container_definitions = "[{\"name\":\"numeric-uid-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"1000\"}]"
  }
}

# FAIL: Host mode with privileged=false and user=root
resource "aws_ecs_task_definition" "fail_host_mode_privileged_false_user_root" {
  expect_failure = true
  attrs = {
    family = "test-task-insecure1"
    network_mode = "host"
    container_definitions = "[{\"name\":\"insecure-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"root\"}]"
  }
}

# FAIL: Host mode with privileged=false and no user
resource "aws_ecs_task_definition" "fail_host_mode_privileged_false_no_user" {
  expect_failure = true
  attrs = {
    family = "test-task-insecure2"
    network_mode = "host"
    container_definitions = "[{\"name\":\"no-user-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false}]"
  }
}

# FAIL: Host mode with no privileged and user=root
resource "aws_ecs_task_definition" "fail_host_mode_no_privileged_user_root" {
  expect_failure = true
  attrs = {
    family = "test-task-insecure3"
    network_mode = "host"
    container_definitions = "[{\"name\":\"default-privileged-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"user\":\"root\"}]"
  }
}

# FAIL: Host mode with no privileged and no user
resource "aws_ecs_task_definition" "fail_host_mode_no_privileged_no_user" {
  expect_failure = true
  attrs = {
    family = "test-task-insecure4"
    network_mode = "host"
    container_definitions = "[{\"name\":\"all-defaults-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true}]"
  }
}

# FAIL: Host mode with multiple containers (one secure, one insecure)
resource "aws_ecs_task_definition" "fail_host_mode_mixed_containers" {
  expect_failure = true
  attrs = {
    family = "test-task-mixed"
    network_mode = "host"
    container_definitions = "[{\"name\":\"secure-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true},{\"name\":\"insecure-container\",\"image\":\"app:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"root\"}]"
  }
}

# PASS: Host mode with multiple secure containers
resource "aws_ecs_task_definition" "pass_host_mode_all_secure_containers" {
  attrs = {
    family = "test-task-allsecure"
    network_mode = "host"
    container_definitions = "[{\"name\":\"privileged-container\",\"image\":\"nginx:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":true},{\"name\":\"nonroot-container\",\"image\":\"app:latest\",\"cpu\":256,\"memory\":512,\"essential\":true,\"privileged\":false,\"user\":\"appuser\"}]"
  }
}