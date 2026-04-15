resource "aws_dms_replication_instance" "validation_test" {
  replication_instance_id    = "test-dms-instance"
  replication_instance_class = "dms.t2.micro"
  auto_minor_version_upgrade = true
  allocated_storage          = 50
}