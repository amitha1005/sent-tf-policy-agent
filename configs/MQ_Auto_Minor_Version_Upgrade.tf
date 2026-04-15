resource "aws_mq_broker" "validation_test" {
  broker_name             = "test-broker"
  engine_type             = "ActiveMQ"
  engine_version          = "5.15.0"
  host_instance_type      = "mq.t3.micro"
  auto_minor_version_upgrade = true
  
  user {
    username = "admin"
    password = "TestPassword123!"
  }
}