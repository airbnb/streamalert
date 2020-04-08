// IAM Role Policy: Allow Rules Engine to read DynamoDB table (Threat Intel)
resource "aws_iam_role_policy" "read_threat_intel_table" {
  count  = var.threat_intel_enabled ? 1 : 0
  name   = "ReadThreatIntelDynamoDB"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.read_threat_intel_table.json
}

// IAM Policy Doc: Allow lambda function to read/write data from DynamoDB
data "aws_iam_policy_document" "read_threat_intel_table" {
  statement {
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:GetItem",
    ]

    resources = [
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.dynamodb_table_name}",
    ]
  }
}

// Allow the Rules Engine to read the rules table
resource "aws_iam_role_policy" "read_rules_table" {
  count  = var.enable_rule_staging ? 1 : 0
  name   = "ReadRulesDynamoDB"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.read_rules_table[0].json
}

data "aws_iam_policy_document" "read_rules_table" {
  count = var.enable_rule_staging ? 1 : 0

  statement {
    effect = "Allow"

    actions = [
      "dynamodb:Scan",
    ]

    resources = [
      var.rules_table_arn,
    ]
  }
}

// Policy for Rules Engine
data "aws_iam_policy_document" "rules_engine_policy" {
  statement {
    sid = "AllowSSE"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = [var.classifier_sqs_sse_kms_key_arn]
  }

  statement {
    sid = "ProcessSQSMessages"

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]

    resources = [var.classifier_sqs_queue_arn]
  }
}

resource "aws_iam_role_policy" "rules_engine_policy" {
  name   = "SQSReadAndDecrypt"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.rules_engine_policy.json
}

// IAM Role Policy: Allow the Rules Engine to save alerts to dynamo.
resource "aws_iam_role_policy" "save_alerts_to_dynamo" {
  name   = "WriteAlertsDynamoDB"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.save_alerts_to_dynamo.json
}

data "aws_iam_policy_document" "save_alerts_to_dynamo" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:BatchWriteItem"]
    resources = ["arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.prefix}_streamalert_alerts"]
  }
}
