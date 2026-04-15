# Test configuration for aws_guardduty_detector
resource "aws_guardduty_detector" "test" {
  enable = true
  finding_publishing_frequency = "SIX_HOURS"
}

# Test configuration for aws_guardduty_detector_feature
resource "aws_guardduty_detector_feature" "test" {
  detector_id = aws_guardduty_detector.test.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"
}