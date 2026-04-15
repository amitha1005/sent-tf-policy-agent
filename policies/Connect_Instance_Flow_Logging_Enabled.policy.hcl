# Connect Instance Flow Logging Should Be Enabled
#
# This policy ensures that AWS Connect instances have contact flow logging enabled.
# This is required for compliance and auditing purposes.
#
# Converted from Sentinel policy: connect-instance-flow-logging-should-be-enabled
#
# Resources checked:
# - aws_connect_instance
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/connect-controls.html#connect-2

policy {}

resource_policy "aws_connect_instance" "contact_flow_logs_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get contact_flow_logs_enabled value, defaulting to false if not set
        contact_flow_logs_enabled = core::try(attrs.contact_flow_logs_enabled, false)
    }

    enforce {
        condition = local.contact_flow_logs_enabled == true
        error_message = "Attribute 'contact_flow_logs_enabled' must be true for 'aws_connect_instance' resource '${meta.address}'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/connect-controls.html#connect-2 for more details."
    }
}