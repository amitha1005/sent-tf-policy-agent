# LIMITATION: This policy evaluates resources in the planned state but cannot reliably verify
# configuration-level references between resources. The Sentinel policy uses tfconfig metadata
# to trace references between aws_lb, aws_lb_listener, and aws_lb_listener_rule resources.
# TF Policy can only match resources by attribute values in the planned state, which may not
# be resolved for new resources with cross-references. This implementation checks for proper
# HTTP-to-HTTPS redirect configuration but may not accurately validate the complete relationship
# chain between load balancers, listeners, and listener rules for newly created resources.

policy {}

# Get all listeners and listener rules once at top level for performance
locals {
    all_listeners = core::getresources("aws_lb_listener", {})
    all_listener_rules = core::getresources("aws_lb_listener_rule", {})
}

# Check aws_lb resources to ensure application load balancers have proper HTTP redirection
resource_policy "aws_lb" "http_to_https_redirect" {
    # Only check application load balancers
    filter = core::try(attrs.load_balancer_type, "application") == "application"

    locals {
        # Get the ARN of the current load balancer
        lb_arn = attrs.arn

        # Find all HTTP listeners (port 80, protocol HTTP) associated with this load balancer
        http_listeners_for_this_lb = [
            for listener in local.all_listeners :
            listener if (
                listener.load_balancer_arn == local.lb_arn &&
                core::try(listener.protocol, "HTTP") == "HTTP" &&
                core::try(listener.port, 0) == 80
            )
        ]

        # Helper function to check if a listener has inline HTTPS redirect
        listeners_with_inline_redirect = [
            for listener in local.http_listeners_for_this_lb :
            listener if core::length([
                for action in core::try(listener.default_action, []) :
                action if (
                    action.type == "redirect" &&
                    core::try(action.redirect[0].protocol, "") == "HTTPS" &&
                    core::try(action.redirect[0].port, "") == "443"
                )
            ]) > 0
        ]

        # Check if HTTP listeners have associated listener rules with redirect
        listeners_with_rule_redirect = [
            for listener in local.http_listeners_for_this_lb :
            listener if core::length([
                for rule in local.all_listener_rules :
                rule if (
                    rule.listener_arn == listener.arn &&
                    core::length([
                        for action in core::try(rule.action, []) :
                        action if (
                            action.type == "redirect" &&
                            core::try(action.redirect[0].protocol, "") == "HTTPS" &&
                            core::try(action.redirect[0].port, "") == "443"
                        )
                    ]) > 0
                )
            ]) > 0
        ]

        # Combine both redirect methods
        valid_redirects_count = core::length(local.listeners_with_inline_redirect) + core::length(local.listeners_with_rule_redirect)
        
        # Check if we have any HTTP listeners
        has_http_listeners = core::length(local.http_listeners_for_this_lb) > 0
        
        # If we have HTTP listeners, we must have at least one valid redirect
        has_valid_redirect = !local.has_http_listeners || local.valid_redirects_count > 0
    }

    enforce {
        condition = local.has_valid_redirect
        error_message = "Application load balancers should be configured to redirect all HTTP requests to HTTPS. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-1 for more details."
    }
}