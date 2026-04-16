# Ensure AWS MQ Brokers have auto minor version upgrade enabled
#
# This policy checks if resources of type 'aws_mq_broker' have the 
# 'auto_minor_version_upgrade' attribute set to true to ensure brokers
# automatically receive minor version updates and security patches.
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/mq-controls.html#mq-3
#
# Converted from Sentinel Policy: mq-auto-minor-version-upgrade-enabled

policy {}

resource_policy "aws_mq_broker" "auto_minor_version_upgrade_enabled" {

  enforcement_level = "advisory"
    locals {
        # Extract auto_minor_version_upgrade value, default to false if not set
        auto_upgrade_enabled = core::try(attrs.auto_minor_version_upgrade, false)
    }

    enforce {
        condition = local.auto_upgrade_enabled == true
  error_message = "Attribute 'auto_minor_version_upgrade' should be true for AWS MQ Broker. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/mq-controls.html#mq-3 for more details."
    }
}