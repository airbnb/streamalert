data "aws_iam_policy_document" "lambda_execution_policy" {
  count = "${var.enabled}"

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// Create the execution role for the Lambda function.
resource "aws_iam_role" "role" {
  count              = "${var.enabled}"
  name               = "${var.function_name}_role"
  assume_role_policy = "${data.aws_iam_policy_document.lambda_execution_policy.json}"
}

// Base permissions - Allow creating logs and publishing metrics
data "aws_iam_policy_document" "logs_metrics_policy" {
  statement {
    effect = "Allow"

    actions = [
      "cloudwatch:PutMetricData",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "logs_metrics_policy" {
  count  = "${var.enabled}"
  name   = "LogsAndMetrics"
  role   = "${aws_iam_role.role.id}"
  policy = "${data.aws_iam_policy_document.logs_metrics_policy.json}"
}
