// Allow the Alert Merger to query and update the alerts table
resource "aws_iam_role_policy" "manage_alerts_table" {
  name   = "ManageAlertsTable"
  role   = var.role_id
  policy = data.aws_iam_policy_document.manage_alerts_table.json
}

data "aws_iam_policy_document" "manage_alerts_table" {
  statement {
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
    ]

    resources = ["arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.prefix}_streamalert_alerts"]
  }
}

// Allow the Alert Merger to invoke the Alert Processor
resource "aws_iam_role_policy" "invoke_alert_processor" {
  name   = "InvokeAlertProcessor"
  role   = var.role_id
  policy = data.aws_iam_policy_document.invoke_alert_processor.json
}

data "aws_iam_policy_document" "invoke_alert_processor" {
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_streamalert_alert_processor"]
  }
}
