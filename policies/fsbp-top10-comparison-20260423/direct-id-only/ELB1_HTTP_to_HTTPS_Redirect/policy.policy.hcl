# [ELB.1] Application Load Balancer should be configured to redirect all HTTP requests to HTTPS
#
# This policy enforces AWS Security Hub control ELB.1, ensuring that all HTTP listeners
# on Application Load Balancers redirect requests to HTTPS to enforce encryption in transit.
#
# Control ID: ELB.1
# Source: AWS Security Hub
# Severity: Medium
# Compliance: PCI DSS v3.2.1
#
# Resources checked:
# - aws_lb_listener (HTTP listeners on port 80)
#
# Pass criteria:
# - HTTP listener has default_action type "redirect"
# - Redirect targets HTTPS protocol on port 443
# - Status code is HTTP_301 or HTTP_302
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-1

policy {}

# Check HTTP listeners on port 80 for proper HTTPS redirect configuration
resource_policy "aws_lb_listener" "http_to_https_redirect" {
    # Only evaluate HTTP listeners on port 80
    filter = attrs.protocol == "HTTP" && attrs.port == 80

    locals {
        # Get the default action (should be a list with at least one action)
        default_actions = core::try(attrs.default_action, [])
        has_actions = core::length(local.default_actions) > 0
        
        # Get the first default action
        first_action = local.has_actions ? local.default_actions[0] : null
        action_type = local.first_action != null ? core::try(local.first_action.type, "") : ""
        
        # Check if action type is redirect
        is_redirect = local.action_type == "redirect"
        
        # Get redirect configuration
        redirect_config = local.is_redirect ? core::try(local.first_action.redirect, null) : null
        has_redirect_config = local.redirect_config != null ? core::length(local.redirect_config) > 0 : false
        
        # Extract redirect details (redirect is a list, get first element)
        redirect_block = local.has_redirect_config ? local.redirect_config[0] : null
        redirect_protocol = local.redirect_block != null ? core::try(local.redirect_block.protocol, "") : ""
        redirect_port = local.redirect_block != null ? core::try(local.redirect_block.port, "") : ""
        redirect_status = local.redirect_block != null ? core::try(local.redirect_block.status_code, "") : ""
        
        # Validate redirect configuration
        protocol_valid = local.redirect_protocol == "HTTPS" || local.redirect_protocol == "#{protocol}"
        port_valid = local.redirect_port == "443" || local.redirect_port == "#{port}"
        status_valid = local.redirect_status == "HTTP_301" || local.redirect_status == "HTTP_302"
        
        # Check if redirect is properly configured
        redirect_properly_configured = local.is_redirect && local.has_redirect_config && local.protocol_valid && local.port_valid && local.status_valid
    }

    enforce {
        condition = local.redirect_properly_configured
        error_message = "HTTP listener on port 80 must redirect to HTTPS on port 443. Configure default_action with type='redirect', redirect.protocol='HTTPS', redirect.port='443', and redirect.status_code='HTTP_301' or 'HTTP_302'. Current configuration: action_type='${local.action_type}', redirect_protocol='${local.redirect_protocol}', redirect_port='${local.redirect_port}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-1 for more details."
    }
}