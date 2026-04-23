provider "aws" {
  region = "us-east-1"
}

# Test aws_security_group resource with ingress rules
resource "aws_security_group" "test_sg" {
  name        = "test-security-group"
  description = "Test security group for validation"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "test-sg"
  }
}

# Test aws_vpc_security_group_ingress_rule resource (newer pattern)
resource "aws_vpc_security_group_ingress_rule" "test_ingress" {
  security_group_id = aws_security_group.test_sg.id
  
  ip_protocol = "tcp"
  from_port   = 22
  to_port     = 22
  cidr_ipv4   = "0.0.0.0/0"
  
  description = "Test ingress rule"
}

# Test aws_security_group_rule resource (deprecated but still in use)
resource "aws_security_group_rule" "test_rule" {
  type              = "ingress"
  security_group_id = aws_security_group.test_sg.id
  
  protocol    = "tcp"
  from_port   = 3389
  to_port     = 3389
  cidr_blocks = ["0.0.0.0/0"]
  
  description = "Test security group rule"
}

# Test aws_default_security_group resource
resource "aws_default_security_group" "test_default" {
  vpc_id = "vpc-12345678"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "default-sg-test"
  }
}