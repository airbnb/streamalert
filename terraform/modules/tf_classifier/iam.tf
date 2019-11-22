resource "aws_iam_role_policy" "classifier_policy" {
  name   = "WriteAndEncryptSQS"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.classifier_policy.json
}

# Sending messages to the classifier SQS queue
data "aws_iam_policy_document" "classifier_policy" {
  statement {
    sid = "AllowSSE"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = [var.classifier_sqs_sse_kms_key_arn]
  }

  statement {
    sid       = "AllowPublishToQueue"
    actions   = ["sqs:SendMessage*"]
    resources = [var.classifier_sqs_queue_arn]
  }
}
