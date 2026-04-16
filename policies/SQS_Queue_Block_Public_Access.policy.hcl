# LIMITATION: Cross-Resource Reference Validation
# 
# This policy has inherent limitations due to TF Policy's technical constraints:
# - Cannot access config-level reference metadata (config.attribute["references"])
# - Cannot verify if aws_sqs_queue_policy.policy actually references a specific aws_iam_policy_document
# - Uses attribute value matching in planned state instead of reference tracking
# - New resources with unresolved cross-references may not match reliably
#
# Original Sentinel behavior:
# - Tracks references from aws_sqs_queue_policy.policy to aws_iam_policy_document via metadata
# - Validates the content of the referenced policy document
# - Matches queue URLs to ensure all queues have proper policies
#
# TF Policy implementation:
# - Finds aws_sqs_queue resources
# - Finds aws_sqs_queue_policy resources and matches them to queues by queue_url
# - For policies with JSON content, parses and validates statements
# - Cannot reliably track data source references, so validates inline policies only
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html#sqs-3

policy {}

# Check aws_sqs_queue resources - ensure they have corresponding non-public queue policies
resource_policy "aws_sqs_queue" "block_public_access" {
  enforcement_level = "advisory"
    locals {
        # Get all queue policies to check coverage
        all_queue_policies = [for p in core::getresources("aws_sqs_queue_policy", null) : p]
        
        # Get the queue URL/ARN for this queue (could be computed, so may be null during plan)
        queue_url = core::try(attrs.url, null)
        queue_arn = core::try(attrs.arn, null)
        queue_name = core::try(attrs.name, null)
        
        # Check if this queue has a corresponding policy
        # Note: This is best-effort matching since we can't access reference metadata
        has_policy = core::length([
            for p in local.all_queue_policies : p
            if (p.queue_url != null && local.queue_url != null && p.queue_url == local.queue_url)
        ]) > 0
    }
    
    enforce {
        condition = local.has_policy || local.queue_url == null
  error_message = "SQS queue does not have an associated aws_sqs_queue_policy resource. SQS queue access policies should not allow public access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html#sqs-3 for more details."
    }
}

# Check aws_sqs_queue_policy resources - ensure they don't allow public access
resource_policy "aws_sqs_queue_policy" "no_public_access" {
  enforcement_level = "advisory"
    locals {
        # Get the policy content (JSON string)
        policy_json = core::try(attrs.policy, "")
        
        # Parse the policy JSON if possible
        # Note: We can only check inline JSON policies, not data source references
        # The Sentinel version could follow references, but TF Policy cannot
        policy_parsed = local.policy_json != "" ? jsondecode(local.policy_json) : {}
        
        # Extract statements
        statements = core::try(local.policy_parsed.Statement, [])
        
        # Check for public access: Effect=Allow AND Principal contains "*" or {"AWS": "*"}
        has_public_allow = core::anytrue([
            for stmt in local.statements : (
                core::try(stmt.Effect, "") == "Allow" &&
                (
                    # Direct wildcard principal
                    (core::try(stmt.Principal, null) == "*") ||
                    # AWS principal with wildcard
                    (
                        core::try(stmt.Principal, null) != null &&
                        core::try(stmt.Principal.AWS, null) != null &&
                        (
                            stmt.Principal.AWS == "*" ||
                            (
                                core::try(core::length(stmt.Principal.AWS), 0) > 0 &&
                                core::contains(stmt.Principal.AWS, "*")
                            )
                        )
                    )
                )
            )
        ])
    }
    
    enforce {
        condition = local.policy_json == "" || !local.has_public_allow
  error_message = "SQS queue policy allows public access. The policy contains an Allow statement with a wildcard (*) principal. SQS queue access policies should not allow public access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html#sqs-3 for more details."
    }
}