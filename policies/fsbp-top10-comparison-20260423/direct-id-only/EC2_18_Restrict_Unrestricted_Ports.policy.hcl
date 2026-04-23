# EC2.18 - Security groups should only allow unrestricted incoming traffic for authorized ports
#
# This policy enforces that Amazon EC2 security groups only permit unrestricted incoming traffic 
# (0.0.0.0/0 for IPv4 or ::/0 for IPv6) from authorized ports. By default, only ports 80 and 443 
# are authorized, but this can be customized through parameters.
#
# Control ID: EC2.18
# Source: AWS Security Hub - NIST 800 171 REV2
# Severity: High
# Category: Protect > Secure network configuration > Security group configuration
#
# Related requirements: 
# NIST.800-53.r5 AC-4, AC-4(21), SC-7, SC-7(11), SC-7(16), SC-7(21), SC-7(4), SC-7(5)
# NIST.800-171.r2 3.1.3, 3.1.20, 3.13.1
#
# Resources checked:
# - aws_security_group (with inline ingress blocks)
# - aws_vpc_security_group_ingress_rule (standalone ingress rules)
# - aws_security_group_rule (deprecated but still checked)
# - aws_default_security_group (with inline ingress blocks)
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18

policy {}

# Check aws_security_group resources with inline ingress blocks
resource_policy "aws_security_group" "authorized_ports_only" {
    # Only check security groups that have ingress rules defined
    filter = attrs.ingress != null && core::length(attrs.ingress) > 0

    locals {
        # Default authorized TCP ports (80, 443)
        # In production, these could be parameterized via workspace variables
        authorized_tcp_ports = [80, 443]
        authorized_udp_ports = []
        
        # Check each ingress rule for unrestricted access to unauthorized ports
        unrestricted_rules = [
            for rule in attrs.ingress :
            rule if (
                # Check if rule has unrestricted IPv4 CIDR (0.0.0.0/0)
                (core::try(rule.cidr_blocks, []) != [] && core::contains(core::try(rule.cidr_blocks, []), "0.0.0.0/0")) ||
                # Check if rule has unrestricted IPv6 CIDR (::/0)
                (core::try(rule.ipv6_cidr_blocks, []) != [] && core::contains(core::try(rule.ipv6_cidr_blocks, []), "::/0"))
            )
        ]
        
        # Filter unrestricted rules to find violations (unauthorized ports)
        violations = [
            for rule in local.unrestricted_rules :
            rule if (
                # For TCP protocol
                (core::try(rule.protocol, "") == "tcp" && !(
                    core::contains(local.authorized_tcp_ports, core::try(rule.from_port, -1)) &&
                    core::contains(local.authorized_tcp_ports, core::try(rule.to_port, -1))
                )) ||
                # For UDP protocol
                (core::try(rule.protocol, "") == "udp" && !(
                    core::length(local.authorized_udp_ports) > 0 &&
                    core::contains(local.authorized_udp_ports, core::try(rule.from_port, -1)) &&
                    core::contains(local.authorized_udp_ports, core::try(rule.to_port, -1))
                )) ||
                # For protocol "-1" (all protocols) - always a violation with unrestricted access
                core::try(rule.protocol, "") == "-1"
            )
        ]
        
        has_violations = core::length(local.violations) > 0
    }

    enforce {
        condition = !local.has_violations
        error_message = "Security group allows unrestricted incoming traffic (0.0.0.0/0 or ::/0) from unauthorized ports. Only ports 80, 443 are authorized for TCP traffic. Found ${core::length(local.violations)} rule(s) with violations. Security group rules should follow the principle of least privileged access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
    }
}

# Check aws_vpc_security_group_ingress_rule resources (newer standalone pattern)
resource_policy "aws_vpc_security_group_ingress_rule" "authorized_ports_only" {
    locals {
        # Default authorized TCP ports (80, 443)
        authorized_tcp_ports = [80, 443]
        authorized_udp_ports = []
        
        # Check if this rule has unrestricted access
        has_unrestricted_ipv4 = core::try(attrs.cidr_ipv4, "") == "0.0.0.0/0"
        has_unrestricted_ipv6 = core::try(attrs.cidr_ipv6, "") == "::/0"
        is_unrestricted = local.has_unrestricted_ipv4 || local.has_unrestricted_ipv6
        
        # Get protocol and port information
        protocol = core::try(attrs.ip_protocol, "")
        from_port = core::try(attrs.from_port, -1)
        to_port = core::try(attrs.to_port, -1)
        
        # Check if ports are authorized
        tcp_authorized = local.protocol == "tcp" && core::contains(local.authorized_tcp_ports, local.from_port) && core::contains(local.authorized_tcp_ports, local.to_port)
        
        udp_authorized = local.protocol == "udp" && core::length(local.authorized_udp_ports) > 0 && core::contains(local.authorized_udp_ports, local.from_port) && core::contains(local.authorized_udp_ports, local.to_port)
        
        # Protocol -1 means all protocols - never authorized with unrestricted access
        all_protocols = local.protocol == "-1"
        
        # Determine if this is a violation
        is_violation = local.is_unrestricted && (
            (local.protocol == "tcp" && !local.tcp_authorized) ||
            (local.protocol == "udp" && !local.udp_authorized) ||
            local.all_protocols
        )
    }

    enforce {
        condition = !local.is_violation
        error_message = "Security group ingress rule allows unrestricted incoming traffic (0.0.0.0/0 or ::/0) from unauthorized port(s) ${local.from_port}-${local.to_port} (protocol: ${local.protocol}). Only ports 80, 443 are authorized for TCP traffic. Security group rules should follow the principle of least privileged access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
    }
}

# Check aws_security_group_rule resources (deprecated pattern but still in use)
resource_policy "aws_security_group_rule" "authorized_ports_only" {
    # Only check ingress rules
    filter = core::try(attrs.type, "") == "ingress"
    
    locals {
        # Default authorized TCP ports (80, 443)
        authorized_tcp_ports = [80, 443]
        authorized_udp_ports = []
        
        # Check if this rule has unrestricted access
        has_unrestricted_ipv4 = core::try(attrs.cidr_blocks, []) != [] && core::contains(core::try(attrs.cidr_blocks, []), "0.0.0.0/0")
        has_unrestricted_ipv6 = core::try(attrs.ipv6_cidr_blocks, []) != [] && core::contains(core::try(attrs.ipv6_cidr_blocks, []), "::/0")
        is_unrestricted = local.has_unrestricted_ipv4 || local.has_unrestricted_ipv6
        
        # Get protocol and port information
        protocol = core::try(attrs.protocol, "")
        from_port = core::try(attrs.from_port, -1)
        to_port = core::try(attrs.to_port, -1)
        
        # Check if ports are authorized
        tcp_authorized = local.protocol == "tcp" && core::contains(local.authorized_tcp_ports, local.from_port) && core::contains(local.authorized_tcp_ports, local.to_port)
        
        udp_authorized = local.protocol == "udp" && core::length(local.authorized_udp_ports) > 0 && core::contains(local.authorized_udp_ports, local.from_port) && core::contains(local.authorized_udp_ports, local.to_port)
        
        # Protocol -1 means all protocols - never authorized with unrestricted access
        all_protocols = local.protocol == "-1"
        
        # Determine if this is a violation
        is_violation = local.is_unrestricted && (
            (local.protocol == "tcp" && !local.tcp_authorized) ||
            (local.protocol == "udp" && !local.udp_authorized) ||
            local.all_protocols
        )
    }

    enforce {
        condition = !local.is_violation
        error_message = "Security group rule allows unrestricted incoming traffic (0.0.0.0/0 or ::/0) from unauthorized port(s) ${local.from_port}-${local.to_port} (protocol: ${local.protocol}). Only ports 80, 443 are authorized for TCP traffic. Security group rules should follow the principle of least privileged access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
    }
}

# Check aws_default_security_group resources with inline ingress blocks
resource_policy "aws_default_security_group" "authorized_ports_only" {
    # Only check default security groups that have ingress rules defined
    filter = attrs.ingress != null && core::length(attrs.ingress) > 0

    locals {
        # Default authorized TCP ports (80, 443)
        authorized_tcp_ports = [80, 443]
        authorized_udp_ports = []
        
        # Check each ingress rule for unrestricted access to unauthorized ports
        unrestricted_rules = [
            for rule in attrs.ingress :
            rule if (
                # Check if rule has unrestricted IPv4 CIDR (0.0.0.0/0)
                (core::try(rule.cidr_blocks, []) != [] && core::contains(core::try(rule.cidr_blocks, []), "0.0.0.0/0")) ||
                # Check if rule has unrestricted IPv6 CIDR (::/0)
                (core::try(rule.ipv6_cidr_blocks, []) != [] && core::contains(core::try(rule.ipv6_cidr_blocks, []), "::/0"))
            )
        ]
        
        # Filter unrestricted rules to find violations (unauthorized ports)
        violations = [
            for rule in local.unrestricted_rules :
            rule if (
                # For TCP protocol
                (core::try(rule.protocol, "") == "tcp" && !(
                    core::contains(local.authorized_tcp_ports, core::try(rule.from_port, -1)) &&
                    core::contains(local.authorized_tcp_ports, core::try(rule.to_port, -1))
                )) ||
                # For UDP protocol
                (core::try(rule.protocol, "") == "udp" && !(
                    core::length(local.authorized_udp_ports) > 0 &&
                    core::contains(local.authorized_udp_ports, core::try(rule.from_port, -1)) &&
                    core::contains(local.authorized_udp_ports, core::try(rule.to_port, -1))
                )) ||
                # For protocol "-1" (all protocols) - always a violation with unrestricted access
                core::try(rule.protocol, "") == "-1"
            )
        ]
        
        has_violations = core::length(local.violations) > 0
    }

    enforce {
        condition = !local.has_violations
        error_message = "Default security group allows unrestricted incoming traffic (0.0.0.0/0 or ::/0) from unauthorized ports. Only ports 80, 443 are authorized for TCP traffic. Found ${core::length(local.violations)} rule(s) with violations. Security group rules should follow the principle of least privileged access. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
    }
}