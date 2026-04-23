# ECS.1 - Amazon ECS Task Definitions Secure Networking and User Configuration
#
# Control ID: ECS.1
# Title: Amazon ECS task definitions should have secure networking modes and user definitions
# Source: AWS Security Hub - NIST 800 53 REV5
# Severity: High
# Resource Type: aws_ecs_task_definition
#
# This policy checks whether an active Amazon ECS task definition with host networking mode
# has privileged or user container definitions. The control fails for task definitions that
# have host network mode and container definitions of privileged=false or empty, and
# user=root or empty.
#
# Related Requirements: NIST.800-53.r5 AC-2(1), AC-3, AC-3(15), AC-3(7), AC-5, AC-6
#
# Policy Logic:
# - If network_mode is NOT "host" -> PASS (no security concern)
# - If network_mode is "host":
#   - For each container in container_definitions:
#     - Container is SECURE if: privileged=true OR user is non-root (not "root" and not empty)
#     - Container is INSECURE if: (privileged=false OR missing) AND (user="root" OR missing)
#   - FAIL if ANY container is insecure
#   - PASS if ALL containers are secure

policy {}

resource_policy "aws_ecs_task_definition" "secure_host_mode_configuration" {
    # Only evaluate task definitions that use host network mode
    filter = attrs.network_mode == "host"

    locals {
        # Parse the JSON-encoded container_definitions string
        containers = core::jsondecode(attrs.container_definitions)
        
        # Check each container for secure configuration
        # A container is secure if:
        # 1. privileged is explicitly set to true, OR
        # 2. user is set to a non-root value (not "root" and not null/empty)
        insecure_containers = [
            for container in local.containers :
            container if (
                # Check if privileged is false or missing (insecure)
                core::try(container.privileged, false) == false &&
                # AND user is root or missing (insecure)
                (core::try(container.user, null) == null || core::try(container.user, "") == "" || core::try(container.user, "") == "root")
            )
        ]
        
        # Policy fails if there are any insecure containers
        has_insecure_containers = core::length(local.insecure_containers) > 0
        
        # Build detailed error message
        insecure_container_names = [
            for container in local.insecure_containers :
            core::try(container.name, "unnamed")
        ]
    }

    enforce {
        condition = !local.has_insecure_containers
        error_message = "ECS task definition '${attrs.family}' uses host network mode but has insecure container configurations. The following containers lack proper security settings (must have either privileged=true OR non-root user): ${core::join(", ", local.insecure_container_names)}. When using host network mode, containers must explicitly configure elevated privileges (privileged=true) or use non-root users to prevent unexpected privilege escalation. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-1 for remediation guidance."
    }
}