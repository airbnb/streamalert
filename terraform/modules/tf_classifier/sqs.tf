// SQS Queue Policy: Allow the Classifier to send messages to SQS
resource "aws_sqs_queue_policy" "classifier_queue" {
  queue_url = "${var.classifier_sqs_queue_url}"
  policy    = "${data.aws_iam_policy_document.classifier_queue.json}"
}

// IAM Policy Doc: Allow Classifier to send messages to SQS
data "aws_iam_policy_document" "classifier_queue" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["sqs:SendMessage"]
    resources = ["${var.classifier_sqs_queue_arn}"]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["${var.function_alias_arn}"]
    }
  }
}
