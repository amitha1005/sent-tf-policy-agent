# EC2 Security Group Ingress Traffic Restriction to Unauthorized Ports
#
# This policy ensures that security groups only allow unrestricted incoming traffic 
# from 0.0.0.0/0 or ::/0 to authorized ports.
#
# Converted from Sentinel policy: ec2-security-group-ingress-traffic-restriction-to-unauthorized-ports
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18
#
# Resources checked:
# - aws_security_group_rule (ingress rules)
# - aws_security_group (inline ingress blocks)
# - aws_vpc_security_group_ingress_rule (current best practice)
#
# Authorized ports (modify these lists as needed):
# - TCP: 80, 443
# - UDP: (none)

# Top-level configuration
locals {
  # Authorized TCP ports for unrestricted access
  authorized_tcp_ports = [80, 443]
  
  # Authorized UDP ports for unrestricted access
  authorized_udp_ports = []
}

# Check aws_security_group_rule resources
resource_policy "aws_security_group_rule" "ingress_restriction" {
  # Only evaluate ingress rules
  filter = attrs.type == "ingress"

  locals {
    # Check if rule allows unrestricted IPv4 access
    cidr_blocks = core::try(attrs.cidr_blocks, [])
    has_catchall_ipv4 = core::contains(local.cidr_blocks, "0.0.0.0/0")
    
    # Check if rule allows unrestricted IPv6 access
    ipv6_cidr_blocks = core::try(attrs.ipv6_cidr_blocks, [])
    has_catchall_ipv6 = core::contains(local.ipv6_cidr_blocks, "::/0")
    
    # Check if rule has unrestricted access from any source
    has_unrestricted_access = local.has_catchall_ipv4 || local.has_catchall_ipv6
    
    # Get protocol
    protocol = core::try(attrs.protocol, "")
    
    # Check if protocol is catch-all
    is_catchall_protocol = local.protocol == "all" || local.protocol == "-1"
    
    # Get port range
    from_port = core::try(attrs.from_port, null)
    to_port = core::try(attrs.to_port, null)
    
    # Determine which authorized ports list to use based on protocol
    authorized_ports = local.protocol == "tcp" ? local.authorized_tcp_ports : (local.protocol == "udp" ? local.authorized_udp_ports : [])
    
    # Check if the port range is a single authorized port
    is_single_port = local.from_port == local.to_port
    port_is_authorized = local.is_single_port && core::contains(local.authorized_ports, local.from_port)
    
    # Check if range only includes authorized ports (simplified: from and to must both be in authorized list)
    from_authorized = core::contains(local.authorized_ports, local.from_port)
    to_authorized = core::contains(local.authorized_ports, local.to_port)
    range_is_authorized = local.from_authorized && local.to_authorized
    
    # Rule is compliant if it either:
    # 1. Doesn't have unrestricted access, OR
    # 2. Has unrestricted access but only to authorized ports (not catch-all protocol)
    is_compliant = !local.has_unrestricted_access || (!local.is_catchall_protocol && local.range_is_authorized)
  }

  enforce {
    condition = local.is_compliant
    error_message = "Security group rule should not allow ingress from 0.0.0.0/0 or ::/0 to unauthorized ports. Authorized TCP ports: ${core::join(", ", local.authorized_tcp_ports)}. Authorized UDP ports: ${core::join(", ", local.authorized_udp_ports)}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
  }
}

# Check aws_security_group resources (inline ingress blocks)
resource_policy "aws_security_group" "ingress_restriction" {
  # Only evaluate security groups that have ingress blocks
  filter = attrs.ingress != null && core::length(attrs.ingress) > 0

  locals {
    # Check each ingress block for violations
    violations = [
      for ingress in attrs.ingress : ingress
      if (
        # Check if ingress has unrestricted IPv4 access
        core::contains(core::try(ingress.cidr_blocks, []), "0.0.0.0/0") ||
        # Check if ingress has unrestricted IPv6 access
        core::contains(core::try(ingress.ipv6_cidr_blocks, []), "::/0")
      ) && (
        # Violation if protocol is catch-all
        core::try(ingress.protocol, "") == "all" || core::try(ingress.protocol, "") == "-1" ||
        # OR if ports are not both in authorized list
        !(
          core::contains(
            core::try(ingress.protocol, "") == "tcp" ? local.authorized_tcp_ports : (core::try(ingress.protocol, "") == "udp" ? local.authorized_udp_ports : []),
            core::try(ingress.from_port, -1)
          ) && 
          core::contains(
            core::try(ingress.protocol, "") == "tcp" ? local.authorized_tcp_ports : (core::try(ingress.protocol, "") == "udp" ? local.authorized_udp_ports : []),
            core::try(ingress.to_port, -1)
          )
        )
      )
    ]
    
    is_compliant = core::length(local.violations) == 0
  }

  enforce {
    condition = local.is_compliant
    error_message = "Security group has ${core::length(local.violations)} ingress rule(s) that allow unrestricted traffic from 0.0.0.0/0 or ::/0 to unauthorized ports. Authorized TCP ports: ${core::join(", ", local.authorized_tcp_ports)}. Authorized UDP ports: ${core::join(", ", local.authorized_udp_ports)}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
  }
}

# Check aws_vpc_security_group_ingress_rule resources
resource_policy "aws_vpc_security_group_ingress_rule" "ingress_restriction" {
  locals {
    # Check if rule allows unrestricted IPv4 access
    has_catchall_ipv4 = core::try(attrs.cidr_ipv4, "") == "0.0.0.0/0"
    
    # Check if rule allows unrestricted IPv6 access
    has_catchall_ipv6 = core::try(attrs.cidr_ipv6, "") == "::/0"
    
    # Check if rule has unrestricted access from any source
    has_unrestricted_access = local.has_catchall_ipv4 || local.has_catchall_ipv6
    
    # Get protocol
    ip_protocol = core::try(attrs.ip_protocol, "")
    
    # Check if protocol is catch-all
    is_catchall_protocol = local.ip_protocol == "all" || local.ip_protocol == "-1"
    
    # Get port range
    from_port = core::try(attrs.from_port, null)
    to_port = core::try(attrs.to_port, null)
    
    # Determine which authorized ports list to use based on protocol
    authorized_ports = local.ip_protocol == "tcp" ? local.authorized_tcp_ports : (local.ip_protocol == "udp" ? local.authorized_udp_ports : [])
    
    # Check if range only includes authorized ports (simplified: from and to must both be in authorized list)
    from_authorized = core::contains(local.authorized_ports, local.from_port)
    to_authorized = core::contains(local.authorized_ports, local.to_port)
    range_is_authorized = local.from_authorized && local.to_authorized
    
    # Rule is compliant if it either:
    # 1. Doesn't have unrestricted access, OR
    # 2. Has unrestricted access but only to authorized ports (not catch-all protocol)
    is_compliant = !local.has_unrestricted_access || (!local.is_catchall_protocol && local.range_is_authorized)
  }

  enforce {
    condition = local.is_compliant
    error_message = "VPC security group ingress rule should not allow ingress from 0.0.0.0/0 or ::/0 to unauthorized ports. Authorized TCP ports: ${core::join(", ", local.authorized_tcp_ports)}. Authorized UDP ports: ${core::join(", ", local.authorized_udp_ports)}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18 for more details."
  }
}