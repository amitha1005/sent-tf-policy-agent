# Test configuration for aws_eks_cluster resource validation
resource "aws_eks_cluster" "validation_test" {
  name     = "test-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"
  version  = "1.31"
  
  # The attribute we're validating for the policy
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  vpc_config {
    subnet_ids = [
      "subnet-12345678",
      "subnet-87654321",
    ]
  }
}