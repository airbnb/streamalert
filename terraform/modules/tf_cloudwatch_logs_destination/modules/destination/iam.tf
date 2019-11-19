// IAM Policy Doc: Allow Cross Account CloudWatch Logging
data "aws_iam_policy_document" "cloudwatch_logs_destination_policy" {
  statement {
    sid    = "DestinationPolicy"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = var.account_ids
    }

    actions = [
      "logs:PutSubscriptionFilter",
    ]

    resources = [
      aws_cloudwatch_log_destination.cloudwatch_to_kinesis.arn,
    ]
  }
}
