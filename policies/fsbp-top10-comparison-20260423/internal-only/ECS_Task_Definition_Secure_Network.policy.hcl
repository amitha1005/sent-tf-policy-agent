# ECS Task Definition Secure Networking Mode and User Definitions
#
# This policy ensures that ECS task definitions using host networking mode
# have properly configured container definitions with:
# 1. privileged attribute set to true
# 2. user attribute set to a non-root value
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-1
# Converted from Sentinel policy: ecs-task-definition-secure-networking-mode-and-user-definitions

policy {}

resource_policy "aws_ecs_task_definition" "secure_networking_mode_and_user_definitions" {
    # Only evaluate task definitions with host networking mode
    filter = attrs.network_mode == "host"

    locals {
        # Parse container definitions JSON
        container_definitions_json = core::try(core::jsondecode(attrs.container_definitions), [])
        
        # Check if container_definitions is empty
        has_containers = core::length(local.container_definitions_json) > 0
        
        # Find containers with non-privileged settings (privileged not set or set to false)
        non_privileged_containers = [
            for container in local.container_definitions_json :
            container if core::try(container.privileged, false) != true
        ]
        
        # Find containers with missing or root user
        user_containers = [
            for container in local.container_definitions_json :
            container if core::try(container.user, "") == "" || core::try(container.user, "") == "root"
        ]
        
        # Check if all containers are properly configured
        has_non_privileged = core::length(local.non_privileged_containers) > 0
        has_user_issues = core::length(local.user_containers) > 0
    }

    # Enforce privileged attribute requirement
    enforce {
        condition = !local.has_non_privileged
        error_message = "Attribute 'privileged' should be true for container definitions for the given task definition. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-1 for more details."
    }

    # Enforce user attribute requirement
    enforce {
        condition = !local.has_user_issues
        error_message = "Attribute 'user' should be non empty and should not be 'root' for container definitions for the given task definition. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-1 for more details."
    }
}