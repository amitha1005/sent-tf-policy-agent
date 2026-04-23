provider "aws" {
  region = "us-east-1"
}

# Test resource: aws_security_group_rule
resource "aws_security_group_rule" "test_rule" {
  type              = "ingress"
  from_port         = 80
  to_port           = 443
  protocol          = "tcp"
  security_group_id = "sg-12345678"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
  description       = "Test rule"
}

# Test resource: aws_security_group
resource "aws_security_group" "test_sg" {
  name        = "test-security-group"
  description = "Test security group"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port        = 80
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
    description      = "Test ingress"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Test resource: aws_vpc_security_group_ingress_rule (IPv4 test)
resource "aws_vpc_security_group_ingress_rule" "test_ingress_rule_ipv4" {
  security_group_id = "sg-12345678"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Test ingress rule IPv4"
}

# Test resource: aws_vpc_security_group_ingress_rule (IPv6 test)
resource "aws_vpc_security_group_ingress_rule" "test_ingress_rule_ipv6" {
  security_group_id = "sg-12345678"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 443
  cidr_ipv6         = "::/0"
  description       = "Test ingress rule IPv6"
}