# LIMITATION: This policy has technical constraints due to TF Policy's limitations
#
# This policy validates that aws_sqs_queue resources have associated aws_sqs_queue_policy
# resources by matching queue URLs in the planned state. However, it CANNOT:
# 1. Verify that the policy actually references an aws_iam_policy_document data source
#    (no access to config-level reference metadata)
# 2. Inspect the content of referenced policy documents to check for public access
#    (cannot look up data sources by address or parse JSON policy content)
# 3. Distinguish between hardcoded policy JSON vs data source references
#    (only sees resolved attribute values)
# 4. Detect wildcard principals in policy JSON strings
#    (no string pattern matching or substring search functions available)
#
# The policy matches resources by attribute values in planned state, but cannot verify
# configuration-level references. Resources with unresolved references may not match reliably.
#
# Due to lack of string pattern matching functions, this policy ONLY enforces that queues
# have associated policies, but CANNOT validate the policy content for public access.
#
# Original Sentinel Policy: sqs-queue-block-public-access
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html#sqs-3

policy {}

# Cache all queue policies once for reuse across all queue evaluations
locals {
  all_queue_policies = core::getresources("aws_sqs_queue_policy", null)
}

resource_policy "aws_sqs_queue" "has_policy" {
  locals {
    # Get this queue's URL (computed attribute)
    queue_url = core::try(attrs.url, null)
    
    # Find policies that reference this queue by matching queue_url attribute
    # Note: This matches by resolved values, not configuration references
    matching_policies = [for policy in local.all_queue_policies : policy if core::try(policy.queue_url, "") == local.queue_url]
    
    # Check if at least one policy exists for this queue
    has_associated_policy = core::length(local.matching_policies) > 0
  }
  
  enforce {
    condition = local.has_associated_policy
    error_message = "SQS queue does not have an associated aws_sqs_queue_policy resource. SQS queue access policies should be configured to prevent public access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html#sqs-3 for more details."
  }
}
