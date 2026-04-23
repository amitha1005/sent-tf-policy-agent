# Test cases for EC2 Security Group Ingress Traffic Restriction Policy
# Tests three resource types: aws_security_group_rule, aws_security_group, aws_vpc_security_group_ingress_rule

# ============================================================================
# aws_security_group_rule Tests
# ============================================================================

# PASS: Ingress with authorized TCP port 80 from 0.0.0.0/0
resource "aws_security_group_rule" "pass_tcp_80_ipv4" {
  attrs = {
    type              = "ingress"
    from_port         = 80
    to_port           = 80
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["0.0.0.0/0"]
  }
}

# PASS: Ingress with authorized TCP port 443 from ::/0
resource "aws_security_group_rule" "pass_tcp_443_ipv6" {
  attrs = {
    type              = "ingress"
    from_port         = 443
    to_port           = 443
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    ipv6_cidr_blocks  = ["::/0"]
  }
}

# PASS: Ingress with authorized TCP port range 80-443 from 0.0.0.0/0
resource "aws_security_group_rule" "pass_tcp_80_443_range" {
  attrs = {
    type              = "ingress"
    from_port         = 80
    to_port           = 443
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["0.0.0.0/0"]
  }
}

# FAIL: Ingress with unauthorized TCP port 22 from 0.0.0.0/0
resource "aws_security_group_rule" "fail_tcp_22_ipv4" {
  expect_failure = true
  attrs = {
    type              = "ingress"
    from_port         = 22
    to_port           = 22
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["0.0.0.0/0"]
  }
}

# FAIL: Ingress with unauthorized TCP port 3389 from ::/0
resource "aws_security_group_rule" "fail_tcp_3389_ipv6" {
  expect_failure = true
  attrs = {
    type              = "ingress"
    from_port         = 3389
    to_port           = 3389
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    ipv6_cidr_blocks  = ["::/0"]
  }
}

# FAIL: Ingress with catch-all protocol "all" from 0.0.0.0/0
resource "aws_security_group_rule" "fail_protocol_all_ipv4" {
  expect_failure = true
  attrs = {
    type              = "ingress"
    from_port         = 0
    to_port           = 0
    protocol          = "all"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["0.0.0.0/0"]
  }
}

# FAIL: Ingress with catch-all protocol "-1" from ::/0
resource "aws_security_group_rule" "fail_protocol_minus1_ipv6" {
  expect_failure = true
  attrs = {
    type              = "ingress"
    from_port         = 0
    to_port           = 0
    protocol          = "-1"
    security_group_id = "sg-12345678"
    ipv6_cidr_blocks  = ["::/0"]
  }
}

# PASS: Ingress with restricted CIDR (not 0.0.0.0/0)
resource "aws_security_group_rule" "pass_restricted_cidr" {
  attrs = {
    type              = "ingress"
    from_port         = 22
    to_port           = 22
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["10.0.0.0/8"]
  }
}

# PASS: Egress rule (policy only checks ingress)
resource "aws_security_group_rule" "pass_egress_rule" {
  attrs = {
    type              = "egress"
    from_port         = 0
    to_port           = 0
    protocol          = "-1"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["0.0.0.0/0"]
  }
}

# FAIL: Ingress with port range including unauthorized port (22-80)
resource "aws_security_group_rule" "fail_mixed_port_range" {
  expect_failure = true
  attrs = {
    type              = "ingress"
    from_port         = 22
    to_port           = 80
    protocol          = "tcp"
    security_group_id = "sg-12345678"
    cidr_blocks       = ["0.0.0.0/0"]
  }
}

# ============================================================================
# aws_security_group Tests
# ============================================================================

# PASS: Security group with authorized TCP port 80 in ingress from 0.0.0.0/0
resource "aws_security_group" "pass_sg_tcp_80" {
  attrs = {
    name        = "allow-http"
    description = "Allow HTTP traffic"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# PASS: Security group with authorized TCP ports 80-443 in ingress from ::/0
resource "aws_security_group" "pass_sg_tcp_80_443" {
  attrs = {
    name        = "allow-web"
    description = "Allow web traffic"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port        = 80
        to_port          = 443
        protocol         = "tcp"
        ipv6_cidr_blocks = ["::/0"]
      }
    ]
  }
}

# FAIL: Security group with unauthorized TCP port 3389 from 0.0.0.0/0
resource "aws_security_group" "fail_sg_tcp_3389" {
  expect_failure = true
  attrs = {
    name        = "allow-rdp"
    description = "Allow RDP"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# FAIL: Security group with catch-all protocol from ::/0
resource "aws_security_group" "fail_sg_protocol_all" {
  expect_failure = true
  attrs = {
    name        = "allow-all"
    description = "Allow all traffic"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port        = 0
        to_port          = 0
        protocol         = "all"
        ipv6_cidr_blocks = ["::/0"]
      }
    ]
  }
}

# FAIL: Security group with catch-all protocol "-1" from 0.0.0.0/0
resource "aws_security_group" "fail_sg_protocol_minus1" {
  expect_failure = true
  attrs = {
    name        = "allow-all-minus1"
    description = "Allow all traffic with -1"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# PASS: Security group with restricted CIDR (not unrestricted)
resource "aws_security_group" "pass_sg_restricted_cidr" {
  attrs = {
    name        = "internal-ssh"
    description = "Allow SSH from internal network"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["10.0.0.0/8"]
      }
    ]
  }
}

# PASS: Security group with no ingress blocks
resource "aws_security_group" "pass_sg_no_ingress" {
  attrs = {
    name        = "no-ingress"
    description = "No ingress rules"
    vpc_id      = "vpc-12345678"
    ingress     = []
  }
}

# FAIL: Security group with multiple ingress rules, one violating
resource "aws_security_group" "fail_sg_mixed_rules" {
  expect_failure = true
  attrs = {
    name        = "mixed-rules"
    description = "Mixed compliant and non-compliant rules"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      },
      {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# ============================================================================
# aws_vpc_security_group_ingress_rule Tests
# ============================================================================

# PASS: VPC ingress rule with authorized TCP port 80 from 0.0.0.0/0
resource "aws_vpc_security_group_ingress_rule" "pass_vpc_tcp_80_ipv4" {
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 80
    to_port           = 80
    cidr_ipv4         = "0.0.0.0/0"
  }
}

# PASS: VPC ingress rule with authorized TCP port 443 from ::/0
resource "aws_vpc_security_group_ingress_rule" "pass_vpc_tcp_443_ipv6" {
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 443
    to_port           = 443
    cidr_ipv6         = "::/0"
  }
}

# PASS: VPC ingress rule with authorized TCP port range 80-443 from 0.0.0.0/0
resource "aws_vpc_security_group_ingress_rule" "pass_vpc_tcp_range" {
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 80
    to_port           = 443
    cidr_ipv4         = "0.0.0.0/0"
  }
}

# FAIL: VPC ingress rule with unauthorized UDP port 53 from ::/0
resource "aws_vpc_security_group_ingress_rule" "fail_vpc_udp_53_ipv6" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "udp"
    from_port         = 53
    to_port           = 53
    cidr_ipv6         = "::/0"
  }
}

# FAIL: VPC ingress rule with unauthorized TCP port 22 from 0.0.0.0/0
resource "aws_vpc_security_group_ingress_rule" "fail_vpc_tcp_22_ipv4" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 22
    to_port           = 22
    cidr_ipv4         = "0.0.0.0/0"
  }
}

# FAIL: VPC ingress rule with catch-all protocol "all" from 0.0.0.0/0
resource "aws_vpc_security_group_ingress_rule" "fail_vpc_protocol_all" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "all"
    from_port         = 0
    to_port           = 0
    cidr_ipv4         = "0.0.0.0/0"
  }
}

# FAIL: VPC ingress rule with catch-all protocol "-1" from ::/0
resource "aws_vpc_security_group_ingress_rule" "fail_vpc_protocol_minus1" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "-1"
    from_port         = 0
    to_port           = 0
    cidr_ipv6         = "::/0"
  }
}

# PASS: VPC ingress rule with restricted IPv4 CIDR
resource "aws_vpc_security_group_ingress_rule" "pass_vpc_restricted_ipv4" {
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 22
    to_port           = 22
    cidr_ipv4         = "10.0.0.0/8"
  }
}

# PASS: VPC ingress rule with restricted IPv6 CIDR
resource "aws_vpc_security_group_ingress_rule" "pass_vpc_restricted_ipv6" {
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 3389
    to_port           = 3389
    cidr_ipv6         = "2001:db8::/32"
  }
}

# FAIL: VPC ingress rule with port range including unauthorized ports
resource "aws_vpc_security_group_ingress_rule" "fail_vpc_mixed_port_range" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 22
    to_port           = 80
    cidr_ipv4         = "0.0.0.0/0"
  }
}