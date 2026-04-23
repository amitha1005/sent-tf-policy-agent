# Test cases for EC2.18 - Security groups should only allow unrestricted incoming traffic for authorized ports

# ============================================================================
# aws_security_group tests
# ============================================================================

# PASS: Authorized port 80 with unrestricted IPv4 access
resource "aws_security_group" "sg_pass_authorized_port_80" {
  attrs = {
    name        = "test-sg-80"
    description = "Test security group"
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

# PASS: Authorized port 443 with unrestricted IPv4 access
resource "aws_security_group" "sg_pass_authorized_port_443" {
  attrs = {
    name        = "test-sg-443"
    description = "Test security group"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# PASS: Authorized port 80 with unrestricted IPv6 access
resource "aws_security_group" "sg_pass_authorized_port_80_ipv6" {
  attrs = {
    name        = "test-sg-80-ipv6"
    description = "Test security group"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port        = 80
        to_port          = 80
        protocol         = "tcp"
        ipv6_cidr_blocks = ["::/0"]
      }
    ]
  }
}

# FAIL: Unauthorized port 22 with unrestricted access
resource "aws_security_group" "sg_fail_unauthorized_port_22" {
  expect_failure = true
  attrs = {
    name        = "test-sg-22"
    description = "Test security group"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# FAIL: Unauthorized port 3389 with unrestricted access
resource "aws_security_group" "sg_fail_unauthorized_port_3389" {
  expect_failure = true
  attrs = {
    name        = "test-sg-3389"
    description = "Test security group"
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

# FAIL: Protocol -1 (all protocols) with unrestricted access
resource "aws_security_group" "sg_fail_all_protocols" {
  expect_failure = true
  attrs = {
    name        = "test-sg-all"
    description = "Test security group"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 0
        to_port     = 65535
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# PASS: Restricted CIDR (not unrestricted)
resource "aws_security_group" "sg_pass_restricted_cidr" {
  attrs = {
    name        = "test-sg-restricted"
    description = "Test security group"
    vpc_id      = "vpc-12345678"
    ingress = [
      {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["10.0.0.0/16"]
      }
    ]
  }
}

# ============================================================================
# aws_vpc_security_group_ingress_rule tests
# ============================================================================

# PASS: Authorized port 443 with unrestricted IPv4 access
resource "aws_vpc_security_group_ingress_rule" "ingress_rule_pass_authorized_port_443" {
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 443
    to_port           = 443
    cidr_ipv4         = "0.0.0.0/0"
    description       = "HTTPS access"
  }
}

# FAIL: Unauthorized port 22 with unrestricted IPv4 access
resource "aws_vpc_security_group_ingress_rule" "ingress_rule_fail_unauthorized_port_22" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 22
    to_port           = 22
    cidr_ipv4         = "0.0.0.0/0"
    description       = "SSH access"
  }
}

# FAIL: Unauthorized port 3389 with unrestricted IPv6 access
resource "aws_vpc_security_group_ingress_rule" "ingress_rule_fail_unauthorized_port_3389_ipv6" {
  expect_failure = true
  attrs = {
    security_group_id = "sg-12345678"
    ip_protocol       = "tcp"
    from_port         = 3389
    to_port           = 3389
    cidr_ipv6         = "::/0"
    description       = "RDP access"
  }
}

# ============================================================================
# aws_security_group_rule tests
# ============================================================================

# PASS: Ingress on authorized port 80 with unrestricted access
resource "aws_security_group_rule" "sg_rule_pass_ingress_authorized_port_80" {
  attrs = {
    type              = "ingress"
    security_group_id = "sg-12345678"
    protocol          = "tcp"
    from_port         = 80
    to_port           = 80
    cidr_blocks       = ["0.0.0.0/0"]
    description       = "HTTP access"
  }
}

# FAIL: Ingress on unauthorized port 22 with unrestricted access
resource "aws_security_group_rule" "sg_rule_fail_ingress_unauthorized_port_22" {
  expect_failure = true
  attrs = {
    type              = "ingress"
    security_group_id = "sg-12345678"
    protocol          = "tcp"
    from_port         = 22
    to_port           = 22
    cidr_blocks       = ["0.0.0.0/0"]
    description       = "SSH access"
  }
}

# PASS: Egress rule (not checked by policy)
resource "aws_security_group_rule" "sg_rule_pass_egress_any_port" {
  attrs = {
    type              = "egress"
    security_group_id = "sg-12345678"
    protocol          = "-1"
    from_port         = 0
    to_port           = 0
    cidr_blocks       = ["0.0.0.0/0"]
    description       = "Allow all egress"
  }
}

# ============================================================================
# aws_default_security_group tests
# ============================================================================

# PASS: Default SG with authorized port 443 with unrestricted access
resource "aws_default_security_group" "default_sg_pass_authorized_port_443" {
  attrs = {
    vpc_id = "vpc-12345678"
    ingress = [
      {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}

# FAIL: Default SG with unauthorized port 22 with unrestricted access
resource "aws_default_security_group" "default_sg_fail_unauthorized_port_22" {
  expect_failure = true
  attrs = {
    vpc_id = "vpc-12345678"
    ingress = [
      {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    ]
  }
}