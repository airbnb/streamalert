// SNS topic to send
resource "aws_sns_topic" "digest_sns_topic" {
  name = var.digest_sns_topic
}

// CloudWatch event to trigger Lambda and send digest on a schedule
resource "aws_cloudwatch_event_rule" "send_digest_invocation_schedule" {
  name                = "${var.function_name}_digest_schedule"
  description         = "Invokes ${var.function_name} at ${var.send_digest_schedule_expression}"
  schedule_expression = var.send_digest_schedule_expression

  tags = {
    Name = "StreamAlert"
  }
}

resource "aws_cloudwatch_event_target" "send_digest_invocation" {
  rule  = aws_cloudwatch_event_rule.send_digest_invocation_schedule.name
  arn   = var.function_alias_arn
  input = "{\"send_digest\": true}"
}

// Allow Lambda function to be invoked via a CloudWatch event rule
resource "aws_lambda_permission" "allow_cloudwatch_invocation" {
  statement_id  = "AllowExecutionFromCloudWatch_${var.function_name}_digest_schedule"
  action        = "lambda:InvokeFunction"
  function_name = var.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.send_digest_invocation_schedule.arn
  qualifier     = "production"
}

// Allow the Rule Promotion function to perform necessary actions
resource "aws_iam_role_policy" "rule_promotion_actions" {
  name   = "RulePromotionActions"
  role   = var.role_id
  policy = data.aws_iam_policy_document.rule_promotion_actions.json
}

data "aws_iam_policy_document" "rule_promotion_actions" {
  statement {
    sid    = "PublishDigestToSNS"
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      aws_sns_topic.digest_sns_topic.arn,
    ]
  }

  statement {
    sid    = "ScanAndUpdateDynamoDB"
    effect = "Allow"

    actions = [
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
    ]

    resources = [
      var.rules_table_arn,
    ]
  }

  statement {
    sid    = "AthenaQueryAlerts"
    effect = "Allow"

    actions = [
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StartQueryExecution",
      "glue:GetPartition",
      "glue:GetPartitions",
      "glue:GetTable",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid       = "AthenaDecryptKMS"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.s3_kms_key_arn]
  }

  statement {
    sid    = "AthenaResultsAccess"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
      "s3:CreateBucket",
      "s3:PutObject",
    ]

    resources = [
      "${var.athena_results_bucket_arn}*",
    ]
  }

  statement {
    sid    = "AthenaDataAccess"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${var.alerts_bucket}",
      "arn:aws:s3:::${var.alerts_bucket}/*"
    ]
  }
}
