# Test aws_ebs_volume with encryption
resource "aws_ebs_volume" "validation_test" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = true
  type              = "gp3"
  
  tags = {
    Name = "validation-test"
  }
}

# Test aws_volume_attachment
resource "aws_volume_attachment" "validation_test" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.validation_test.id
  instance_id = "i-1234567890abcdef0"  # Placeholder instance ID
}