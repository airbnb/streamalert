// SNS topic to send
resource "aws_sns_topic" "digest_sns_topic" {
  name = "${var.digest_sns_topic}"
}

// SSM Parameter that stores stat publishing information
resource "aws_ssm_parameter" "stats_publisher_state" {
  name      = "${var.stats_publisher_state_name}"
  type      = "String"
  value     = "${var.stats_publisher_state_value}"
  overwrite = true
}

// Allow the Rule Promotion function to send SNS messages
resource "aws_iam_role_policy" "rule_promotion_actions" {
  name   = "RulePromotionActions"
  role   = "${var.role_id}"
  policy = "${data.aws_iam_policy_document.rule_promotion_actions.json}"
}

data "aws_iam_policy_document" "rule_promotion_actions" {
  statement {
    sid       = "PublishDigestToSNS"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = ["${aws_sns_topic.digest_sns_topic.arn}"]
  }

  statement {
    sid    = "ScanAndUpdateDynamoDB"
    effect = "Allow"

    actions = [
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
    ]

    resources = ["${var.rules_table_arn}"]
  }

  statement {
    sid    = "QueryAthenaAlerts"
    effect = "Allow"

    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryResults",
    ]

    resources = [
      "*",
    ]
  }
}
