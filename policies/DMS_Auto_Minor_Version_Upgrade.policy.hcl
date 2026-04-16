# DMS Auto Minor Version Upgrade Check
#
# This policy ensures that AWS DMS Replication Instances have automatic minor version upgrades enabled.
# This is a conversion from Sentinel policy to Terraform Policy.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/dms-controls.html#dms-6
#
# Resources checked:
# - aws_dms_replication_instance
#
# Sentinel Policy Conversion:
# - Original Sentinel policy checked if 'auto_minor_version_upgrade' is set to true
# - This TF Policy performs the same validation on planned resource values

policy {}

resource_policy "aws_dms_replication_instance" "auto_minor_version_upgrade_check" {

  enforcement_level = "advisory"
    locals {
        # Get the auto_minor_version_upgrade value, defaulting to false if not set
        # This matches the Sentinel behavior using maps.get(res, "values.auto_minor_version_upgrade", false)
        auto_minor_version_upgrade = core::try(attrs.auto_minor_version_upgrade, false)
    }
    
    enforce {
        condition = local.auto_minor_version_upgrade == true
  error_message = "Attribute 'auto_minor_version_upgrade' should be true for AWS DMS Replication Instance. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/dms-controls.html#dms-6 for more details."
    }
}