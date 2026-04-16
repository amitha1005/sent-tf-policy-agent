# AWS Backup Framework Recovery Point Encryption
#
# This policy ensures that AWS Backup Framework resources include a control named
# "BACKUP_RECOVERY_POINT_ENCRYPTED" to enforce encryption of backup recovery points at rest.
#
# Converted from Sentinel policy: backup-recovery-point-encrypted
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/backup-controls.html#backup-1
#
# Resources checked:
# - aws_backup_framework

policy {}

resource_policy "aws_backup_framework" "recovery_point_encrypted" {

  enforcement_level = "advisory"
    locals {
        # Extract control names from the control blocks
        control_names = [for control in attrs.control : core::try(control.name, "")]
        
        # Check if BACKUP_RECOVERY_POINT_ENCRYPTED control exists
        has_encryption_control = core::contains(local.control_names, "BACKUP_RECOVERY_POINT_ENCRYPTED")
    }
    
    enforce {
        condition = local.has_encryption_control
  error_message = "AWS Backup Framework must include a control named 'BACKUP_RECOVERY_POINT_ENCRYPTED'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/backup-controls.html#backup-1 for more details."
    }
}