# ECS Task Definition Secure Networking Mode Policy - Generation Report

## Resource Validation

### Resources Validated
- Resource Type: `aws_ecs_task_definition`
- Validation Status: ✅ Success

### Validated Attributes
- `family`: string - A unique name for your task definition
- `network_mode`: string - Docker networking mode (awsvpc, bridge, host, none)
- `container_definitions`: string (JSON) - List of valid container definitions with properties:
  * `name`: Container name
  * `image`: Docker image to use
  * `cpu`: Number of CPU units
  * `memory`: Memory in MiB
  * `essential`: Whether container is essential
  * `privileged`: Whether to give elevated privileges (relevant to policy)
  * `user`: The user to use inside the container (relevant to policy)
- `requires_compatibilities`: list(string) - Launch types required by the task
- `cpu`: string - Number of CPU units used by the task
- `memory`: string - Amount of memory used by the task

### Terraform Validation Output
```
Success! The configuration is valid.
```

## Policy Generation

### Policy File
- File: [`policy.policy.hcl`](policy.policy.hcl)
- Policy Type: TF Policy
- Policy Name: secure_networking_mode_and_user_definitions

### Policy Code
```hcl
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
```

### Implementation Notes
✅ Policy fully implements all requirements from requirement.txt

The policy successfully converts the Sentinel policy logic to Terraform Policy:
1. Filters task definitions with `network_mode = "host"`
2. Parses the `container_definitions` JSON string using `jsondecode()`
3. Validates that all containers have `privileged = true`
4. Validates that all containers have a non-empty `user` attribute that is not "root"
5. Uses two separate `enforce` blocks for clear error messages

The policy uses:
- `core::try()` for safe attribute access with defaults
- `jsondecode()` to parse the JSON container definitions
- List comprehensions to filter containers that violate the policy
- Multiple `enforce` blocks to provide specific error messages for each violation type

### Verification Status
- ✓ All requirements verified and implemented
- ✓ Policy covers both privileged and user attribute checks
- ✓ Proper error messages with AWS Security Hub references
- ✓ Safe handling of missing or empty container_definitions

## Test Case Generation

### Test Files
- GWT Scenarios: [`gwt.json`](gwt.json)
- Test Cases: [`test.policytest.hcl`](test.policytest.hcl)

### Test Summary
- Total test cases: 9
- Pass scenarios: 3
  * Host network mode with compliant single container
  * Non-host network mode (filtered out)
  * Multiple compliant containers
- Fail scenarios: 6
  * Container with privileged=false
  * Container with missing privileged attribute
  * Container with user='root'
  * Container with missing user attribute
  * Multiple containers with one non-privileged
  * Multiple containers with one root user

### Test Coverage
The test cases cover:
1. ✓ Host network mode with all compliant containers
2. ✓ Non-host network modes (should be filtered out)
3. ✓ Privileged attribute violations (false and missing)
4. ✓ User attribute violations (root and missing)
5. ✓ Multiple container scenarios with mixed compliance
6. ✓ Edge cases with empty and missing attributes

## Test Execution

### Test Command
```
tfpolicy test --policies=.
```

### Test Results
- Status: ✅ Success
- All 9 test cases passed

### Test Output
```
 # test.policytest.hcl... running
   # resource.aws_ecs_task_definition.pass_host_network_privileged_nonroot_user... pass
   # resource.aws_ecs_task_definition.pass_awsvpc_network_mode... pass
   # resource.aws_ecs_task_definition.fail_privileged_false... pass
   # resource.aws_ecs_task_definition.fail_missing_privileged... pass
   # resource.aws_ecs_task_definition.fail_user_root... pass
   # resource.aws_ecs_task_definition.fail_missing_user... pass
   # resource.aws_ecs_task_definition.fail_multiple_containers_privileged... pass
   # resource.aws_ecs_task_definition.fail_multiple_containers_user... pass
   # resource.aws_ecs_task_definition.pass_multiple_containers_compliant... pass
 # test.policytest.hcl... pass
```

### Test Summary
✅ All tests passed successfully!

**Test Results Breakdown:**
- **Pass scenarios (3):** All passed as expected
  * Host network mode with compliant containers
  * Non-host network mode (filtered out)
  * Multiple compliant containers
  
- **Fail scenarios (6):** All correctly detected violations
  * Container with privileged=false
  * Container with missing privileged attribute
  * Container with user='root'
  * Container with missing user attribute
  * Multiple containers with one non-privileged
  * Multiple containers with one root user

### Issues Resolved During Testing
1. **Initial Issue:** Test syntax error - used `test` blocks instead of `resource` blocks
   - **Fix:** Changed to correct `.policytest.hcl` syntax with `resource` blocks
   
2. **Second Issue:** `jsonencode()` not available in test files
   - **Fix:** Provided container_definitions as JSON strings directly
   
3. **Third Issue:** Policy logic not detecting violations - `jsondecode()` needed `core::` prefix
   - **Fix:** Changed `jsondecode()` to `core::jsondecode()`
   - **Fix:** Simplified enforce conditions to directly check violation flags

### Final Status
🎉 **Policy validation complete!** All requirements successfully implemented and tested.