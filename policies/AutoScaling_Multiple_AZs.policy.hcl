# Autoscaling Group Should Cover Multiple Availability Zones
#
# This policy ensures that AWS Auto Scaling Groups are configured to span
# multiple Availability Zones for high availability and resilience.
#
# Resources checked:
# - aws_autoscaling_group
#
# Policy requirement:
# - The 'availability_zones' attribute should contain at least 2 availability zones, OR
# - The 'vpc_zone_identifier' attribute should contain at least 2 subnet IDs
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html#autoscaling-2

policy {}

resource_policy "aws_autoscaling_group" "multiple_azs" {

  enforcement_level = "advisory"
    locals {
        # Safely get availability_zones with default empty list
        availability_zones = core::try(attrs.availability_zones, [])
        
        # Safely get vpc_zone_identifier with default empty list
        vpc_zone_identifier = core::try(attrs.vpc_zone_identifier, [])
        
        # Count availability zones
        az_count = core::length(local.availability_zones)
        
        # Count vpc zone identifiers (subnets)
        vpc_zone_count = core::length(local.vpc_zone_identifier)
        
        # Check if either condition is satisfied (at least 2 AZs or 2 subnets)
        has_multiple_azs = local.az_count > 1 || local.vpc_zone_count > 1
    }
    
    enforce {
        condition = local.has_multiple_azs
        error_message = "Attribute 'availability_zones' or 'vpc_zone_identifier' should have atleast two values for AWS Autoscaling Group '${meta.address}'. Current availability_zones: ${local.az_count}, vpc_zone_identifier: ${local.vpc_zone_count}. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html#autoscaling-2 for more details."
    }
}