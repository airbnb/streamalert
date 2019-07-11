resource "aws_iam_role_policy" "classifier_policy" {
  name   = "${var.function_name}_policy"
  role   = "${var.function_role_id}"
  policy = "${data.aws_iam_policy_document.classifier_policy.json}"
}

# Sending messages to the classifier SQS queue
data "aws_iam_policy_document" "classifier_policy" {
  statement {
    sid = "AllowSSE"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = ["${var.classifier_sqs_sse_kms_key_arn}"]
  }

  statement {
    sid       = "AllowPublishToQueue"
    actions   = ["sqs:SendMessage*"]
    resources = [
      # FIXME (derek.wang) We temporarily grant the classifier privilege to publish to both.
      # this is because there might be in-flight records during deployment that we don't want
      # to get stuck.
      "${var.legacy_classifier_sqs_queue_arn}",
      "${var.new_classifier_sqs_queue_arn}",
    ]
  }
}
