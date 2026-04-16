# Classic Load Balancer HTTPS/TLS Termination Policy
#
# This policy ensures that AWS Classic Load Balancers (aws_elb) have listeners
# configured with HTTPS or TLS termination and proper SSL certificate configuration.
#
# Original Sentinel Policy: elb-configure-https-tls-termination-classic-load-balancer
# AWS Security Hub Control: ELB.3
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-3
#
# Policy Logic:
# 1. If the ELB has listeners configured (not empty)
# 2. Each listener must have lb_protocol set to either "https" or "ssl" (case-insensitive)
# 3. Each listener with HTTPS/SSL protocol must have a non-empty ssl_certificate_id

policy {}

resource_policy "aws_elb" "https_tls_termination" {

  enforcement_level = "advisory"
    # Only evaluate ELBs that have listeners configured
    filter = attrs.listener != null && core::length(attrs.listener) > 0

    locals {
        # Extract all listeners
        listeners = core::try(attrs.listener, [])
        
        # Valid secure protocols (lowercase for case-insensitive comparison)
        valid_protocols = ["https", "ssl"]
        
        # Check each listener for compliance
        compliant_listeners = [
            for listener in local.listeners :
            listener if (
                core::contains(local.valid_protocols, core::try(listener.lb_protocol, "")) &&
                core::try(listener.ssl_certificate_id, "") != ""
            )
        ]
        
        # Policy passes if all listeners are compliant
        all_listeners_compliant = core::length(local.compliant_listeners) == core::length(local.listeners)
    }

    enforce {
        condition = local.all_listeners_compliant
  error_message = "Classic Load Balancer listeners should be configured with HTTPS or TLS termination. Each listener must have 'lb_protocol' set to 'https' or 'ssl' and a non-empty 'ssl_certificate_id'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-3 for more details."
    }
}