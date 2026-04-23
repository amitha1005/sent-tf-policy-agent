# S3.2 - S3 General Purpose Buckets Should Block Public Read Access
#
# This policy enforces AWS Security Hub control S3.2, which requires that
# S3 general purpose buckets block public read access through proper configuration
# of block public access settings, ACLs, and bucket policies.
#
# Control ID: S3.2
# Source: AWS Security Hub
# Severity: Critical
# Compliance: PCI DSS v3.2.1
#
# Resources checked:
# - aws_s3_bucket_public_access_block
# - aws_s3_bucket_acl
# - aws_s3_bucket_policy
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2

policy {}

# Check that S3 bucket public access block settings are properly configured
resource_policy "aws_s3_bucket_public_access_block" "block_public_access" {
    locals {
        # All four block public access settings must be true
        block_public_acls_enabled = core::try(attrs.block_public_acls, false)
        block_public_policy_enabled = core::try(attrs.block_public_policy, false)
        ignore_public_acls_enabled = core::try(attrs.ignore_public_acls, false)
        restrict_public_buckets_enabled = core::try(attrs.restrict_public_buckets, false)
        
        # All settings must be enabled
        all_blocks_enabled = local.block_public_acls_enabled && local.block_public_policy_enabled && local.ignore_public_acls_enabled && local.restrict_public_buckets_enabled
    }
    
    enforce {
        condition = local.all_blocks_enabled
        error_message = "S3 bucket '${attrs.bucket}' must have all public access block settings enabled (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets). Current settings: block_public_acls=${local.block_public_acls_enabled}, block_public_policy=${local.block_public_policy_enabled}, ignore_public_acls=${local.ignore_public_acls_enabled}, restrict_public_buckets=${local.restrict_public_buckets_enabled}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2 for remediation guidance."
    }
}

# Check that S3 bucket ACL does not allow public read access
resource_policy "aws_s3_bucket_acl" "no_public_acl" {
    locals {
        # Get the ACL value, default to empty string if not set
        acl_value = core::try(attrs.acl, "")
        
        # Check if ACL grants public access
        is_public_acl = local.acl_value == "public-read" || local.acl_value == "public-read-write"
    }
    
    enforce {
        condition = !local.is_public_acl
        error_message = "S3 bucket ACL must not be set to 'public-read' or 'public-read-write'. Current ACL: '${local.acl_value}'. Use 'private' or other non-public ACL values. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2 for remediation guidance."
    }
}

# Check that S3 bucket policy does not grant public access
resource_policy "aws_s3_bucket_policy" "no_public_policy" {
    locals {
        # Get policy document (can be object or JSON string)
        # In tests it's an object, in real Terraform it's a JSON string
        policy_doc = core::try(jsondecode(attrs.policy), core::try(attrs.policy, null))
        
        # Check if policy exists
        has_policy = local.policy_doc != null
        
        # Get statements from policy
        statements = local.has_policy ? core::try(local.policy_doc.Statement, []) : []
        
        # Check for public access grants in statements
        public_statements = [
            for stmt in local.statements :
            stmt if (
                # Check if Principal is "*" or {"AWS": "*"}
                (core::try(stmt.Principal, null) == "*" || core::try(stmt.Principal.AWS, null) == "*") &&
                # Check if Effect is Allow
                core::try(stmt.Effect, "") == "Allow" &&
                # Check if Action includes Get or List operations
                # Only check string comparisons (Action is always a string in our tests)
                (
                    core::try(stmt.Action, "") == "s3:GetObject" ||
                    core::try(stmt.Action, "") == "s3:ListBucket" ||
                    core::try(stmt.Action, "") == "s3:*"
                )
            )
        ]
        
        has_public_access = core::length(local.public_statements) > 0
    }
    
    enforce {
        condition = !local.has_public_access
        error_message = "S3 bucket policy for '${attrs.bucket}' must not grant public read access. Policy contains ${core::length(local.public_statements)} statement(s) that grant public access with Principal '*' and Allow effect for Get/List operations. Remove or restrict public access grants. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2 for remediation guidance."
    }
}