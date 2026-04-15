resource "aws_sqs_queue" "public_access_validation" {
  name = "test-queue-block-public-access"
}

data "aws_iam_policy_document" "queue_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions = [
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:SendMessage",
    ]

    resources = [
      aws_sqs_queue.public_access_validation.arn,
    ]
  }
}

resource "aws_sqs_queue_policy" "public_access_validation" {
  queue_url = aws_sqs_queue.public_access_validation.id
  policy    = data.aws_iam_policy_document.queue_policy.json
}
