# Test resource to validate aws_elastic_beanstalk_environment
# and the setting block with cloudwatch log streaming configuration
resource "aws_elastic_beanstalk_application" "test_app" {
  name        = "test-application"
  description = "Test application for validation"
}

resource "aws_elastic_beanstalk_environment" "validation_test" {
  name                = "test-environment"
  application         = aws_elastic_beanstalk_application.test_app.name
  solution_stack_name = "64bit Amazon Linux 2023 v4.0.0 running Python 3.11"

  # Test the setting block with cloudwatch log streaming
  setting {
    namespace = "aws:elasticbeanstalk:cloudwatch:logs"
    name      = "StreamLogs"
    value     = "true"
  }

  # Additional setting to ensure the block structure is correct
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "EnvironmentType"
    value     = "LoadBalanced"
  }
}