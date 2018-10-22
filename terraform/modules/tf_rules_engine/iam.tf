// IAM Role Policy: Allow Rule Processor to read DynamoDB table (Threat Intel)
resource "aws_iam_role_policy" "streamalert_rule_processor_dynamodb" {
  count  = "${var.threat_intel_enabled ? 1 : 0}"
  name   = "ReadDynamodb"
  role   = "${aws_iam_role.streamalert_rule_processor_role.id}"
  policy = "${data.aws_iam_policy_document.streamalert_rule_processor_read_dynamodb.json}"
}

// IAM Policy Doc: Allow lambda function to read/write data from DynamoDB
data "aws_iam_policy_document" "streamalert_rule_processor_read_dynamodb" {
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

// Allow the Rule Processor to read the rules table
resource "aws_iam_role_policy" "read_rules_table" {
  count  = "${var.rules_table_arn == "" ? 0 : 1}"
  name   = "ReadRulesTable"
  role   = "${aws_iam_role.streamalert_rule_processor_role.id}"
  policy = "${data.aws_iam_policy_document.read_rules_table.json}"
}

data "aws_iam_policy_document" "read_rules_table" {
  count = "${var.rules_table_arn == "" ? 0 : 1}"

  statement {
    effect = "Allow"

    actions = [
      "dynamodb:Scan",
    ]

    resources = [
      "${var.rules_table_arn}",
    ]
  }
}

// Policy for Rules Engine
data "aws_iam_policy_document" "rules_engine_policy" {
  statement {
    sid    = "AllowSSE"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = ["${var.sqs_sse_kms_key_arn}"]
  }

  statement {
    sid = "ProcessSQSMessages"

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]

    resources = ["${var.classifier_sqs_queue_arn}"]
  }
}

resource "aws_iam_role_policy" "rules_engine_policy" {
  name   = "${var.prefix}_streamalert_rules_engine_policy"
  role   = "${var.function_role_id}"
  policy = "${data.aws_iam_policy_document.rules_engine_policy.json}"
}
