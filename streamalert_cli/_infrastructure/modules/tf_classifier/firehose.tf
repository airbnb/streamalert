// IAM Role Policy: Allow the Classifier to send data to Firehose
resource "aws_iam_role_policy" "classifier_firehose" {
  name   = "FirehoseWriteData"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.classifier_firehose.json
}

locals {
  stream_prefix = "${var.firehose_use_prefix ? "${var.prefix}_" : ""}streamalert_"
}

// IAM Policy Doc: Allow the Classifier to PutRecord* on any StreamAlert Data Firehose
data "aws_iam_policy_document" "classifier_firehose" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:PutRecord*",
      "firehose:DescribeDeliveryStream",
      "firehose:ListDeliveryStreams",
    ]

    resources = [
      "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/${local.stream_prefix}*",
    ]
  }
}
