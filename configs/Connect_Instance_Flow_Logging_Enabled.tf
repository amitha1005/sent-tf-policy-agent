resource "aws_connect_instance" "validation_test" {
  identity_management_type   = "CONNECT_MANAGED"
  inbound_calls_enabled      = true
  outbound_calls_enabled     = true
  instance_alias             = "test-connect-instance"
  contact_flow_logs_enabled  = true
}