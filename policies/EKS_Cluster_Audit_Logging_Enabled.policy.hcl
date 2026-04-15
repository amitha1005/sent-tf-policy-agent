# EKS Cluster Audit Logging Enabled
#
# This policy ensures that all AWS EKS clusters have audit logging enabled
# as part of their control plane logging configuration.
#
# Converted from Sentinel Policy (IBM Corp. 2024, 2025)
# Original policy: eks-cluster-endpoints-restrict-public-access
#
# Compliance Reference:
# AWS Security Hub Control EKS.8: EKS clusters should have audit logging enabled
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html#eks-8
#
# Resources checked:
# - aws_eks_cluster

policy {}

resource_policy "aws_eks_cluster" "audit_logging_enabled" {

  enforcement_level = "advisory"
    locals {
        # Get enabled_cluster_log_types, default to empty list if not set
        enabled_log_types = core::try(attrs.enabled_cluster_log_types, [])
        
        # Check if "audit" is present in the list
        audit_enabled = core::contains(local.enabled_log_types, "audit")
    }
    
    enforce {
        condition = local.audit_enabled
        error_message = "Audit logging must be enabled for aws_eks_cluster resources. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html#eks-8 for more details."
    }
}