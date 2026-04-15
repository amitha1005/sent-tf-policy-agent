# GuardDuty ECS Runtime Monitoring Policy
#
# This policy ensures that GuardDuty ECS Runtime Monitoring (EKS_RUNTIME_MONITORING) is enabled.
# 
# Converted from Sentinel policy: guardduty-ecs-protection-runtime-enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-12
#
# Resources checked:
# - aws_guardduty_detector: Detector must be enabled
# - aws_guardduty_detector_feature: EKS_RUNTIME_MONITORING feature must be enabled

policy {}

# Check that GuardDuty detector is enabled
resource_policy "aws_guardduty_detector" "detector_enabled" {
  enforcement_level = "advisory"
    locals {
        # Get the enable status, defaulting to false if not set
        detector_enabled = core::try(attrs.enable, false)
    }

    enforce {
        condition = local.detector_enabled == true
        error_message = "GuardDuty ECS Runtime Monitoring should be enabled. GuardDuty detector '${meta.address}' must have 'enable = true'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-12 for more details."
    }
}

# Check that EKS_RUNTIME_MONITORING feature is enabled
resource_policy "aws_guardduty_detector_feature" "runtime_monitoring_enabled" {
  enforcement_level = "advisory"
    locals {
        # Get the feature name, defaulting to empty string if not set
        feature_name = core::try(attrs.name, "")
        
        # Get the feature status, defaulting to empty string if not set
        feature_status = core::try(attrs.status, "")
        
        # Check if this is the EKS_RUNTIME_MONITORING feature
        is_runtime_monitoring = local.feature_name == "EKS_RUNTIME_MONITORING"
        
        # Check if the feature is enabled
        is_enabled = local.feature_status == "ENABLED"
    }

    # Only evaluate resources that are EKS_RUNTIME_MONITORING features
    filter = local.is_runtime_monitoring

    enforce {
        condition = local.is_enabled
        error_message = "GuardDuty ECS Runtime Monitoring should be enabled. Feature '${meta.address}' has name 'EKS_RUNTIME_MONITORING' but status is '${local.feature_status}'. Set 'status = \"ENABLED\"'. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-12 for more details."
    }
}