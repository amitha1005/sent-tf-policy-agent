# ECS Cluster Container Insights Policy
#
# This policy enforces that all AWS ECS clusters have container insights enabled
# to provide monitoring and observability capabilities for containerized applications.
#
# Converted from Sentinel policy: ecs-cluster-enable-container-insights
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-12
#
# Resources checked:
# - aws_ecs_cluster

policy {}

resource_policy "aws_ecs_cluster" "container_insights_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get the setting block(s) from the cluster configuration
        cluster_settings = core::try(attrs.setting, [])
        
        # Check if any setting has name="containerInsights" with value="enabled" or "enhanced"
        container_insights_settings = [
            for setting in local.cluster_settings :
            setting if setting.name == "containerInsights" && (setting.value == "enabled" || setting.value == "enhanced")
        ]
        
        # Container insights is enabled if we found at least one matching setting
        has_container_insights = core::length(local.container_insights_settings) > 0
    }
    
    enforce {
        condition = local.has_container_insights
        error_message = "ECS cluster '${meta.address}' must have container insights enabled. Set 'setting { name = \"containerInsights\", value = \"enabled\" }' in the cluster configuration. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-12 for more details."
    }
}