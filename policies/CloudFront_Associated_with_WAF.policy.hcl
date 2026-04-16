# LIMITATION:
# This policy validates that aws_cloudfront_distribution resources have a web_acl_id
# configured, but cannot verify if the value is a reference to another resource
# (as required by the original Sentinel policy).
#
# The original Sentinel policy checked res.config.web_acl_id["references"] to ensure
# the web_acl_id references another resource (aws_waf_web_acl or aws_wafv2_web_acl).
# TF Policy cannot access configuration-level reference metadata - it only receives
# the resolved attribute values in the planned state.
#
# This implementation validates that web_acl_id is present and not empty, which ensures
# CloudFront distributions are associated with WAF, but cannot distinguish between
# hardcoded ARNs and resource references.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html#cloudfront-6

policy {}

resource_policy "aws_cloudfront_distribution" "associated_with_waf" {

  enforcement_level = "advisory"
  locals {
    # Check if web_acl_id attribute exists and has a non-empty value
    has_web_acl_id = attrs.web_acl_id != null && attrs.web_acl_id != ""
  }

  enforce {
    condition     = local.has_web_acl_id
 error_message = "'aws_cloudfront_distribution' resource must be associated with either AWS WAF Classic or AWS WAF web ACLs. Configure the 'web_acl_id' attribute with a valid WAF web ACL ID or ARN. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html#cloudfront-6 for more details."
  }
}