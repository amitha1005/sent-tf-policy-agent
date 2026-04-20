# Validate aws_sqs_queue resource
resource "aws_sqs_queue" "validation_test" {
  name = "test-queue"
}

# Validate aws_sqs_queue_policy resource
resource "aws_sqs_queue_policy" "validation_test" {
  queue_url = aws_sqs_queue.validation_test.url
  policy    = data.aws_iam_policy_document.sqs_validation_test.json
}

# Validate aws_iam_policy_document data source
data "aws_iam_policy_document" "sqs_validation_test" {
  statement {
    sid    = "TestStatement"
    effect = "Allow"
    
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
    
    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage"
    ]
    
    resources = [
      aws_sqs_queue.validation_test.arn
    ]
  }
}
