// IAM Role: Execution Role
resource "aws_iam_role" "threat_intel_downloader" {
  name               = "${var.prefix}_threat_intel_downloader"
  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

// IAM Policy Doc: Generic Lambda AssumeRole
data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// IAM Role Policy: Allow lambda function to invoke the Lambda Function
resource "aws_iam_role_policy" "threat_intel_downloader" {
  name   = "invoke_lambda_function_role_policy"
  role   = "${aws_iam_role.threat_intel_downloader.id}"
  policy = "${data.aws_iam_policy_document.invoke_lambda_function.json}"
}

// IAM Policy Doc: Allow the lambda function to invoke the Lambda function
data "aws_iam_policy_document" "invoke_lambda_function" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_streamalert_threat_intel_downloader",
    ]
  }
}

// IAM Role Policy: Allow the lambda function to create/update CloudWatch logs
resource "aws_iam_role_policy" "cloudwatch_logs" {
  name   = "cloudwatch_logs_role_policy"
  role   = "${aws_iam_role.threat_intel_downloader.id}"
  policy = "${data.aws_iam_policy_document.cloudwatch_logs_policy.json}"
}

// IAM Policy Doc: Allow the lambda function to create/update CloudWatch logs
data "aws_iam_policy_document" "cloudwatch_logs_policy" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
    ]

    resources = [
      "${aws_cloudwatch_log_group.threat_intel_downloader.arn}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:${aws_cloudwatch_log_group.threat_intel_downloader.name}:log-stream:*",
    ]
  }
}

// IAM role policy: Allow lambda function to read/write data from DynamoDB
resource "aws_iam_role_policy" "read_write_dynamodb" {
  name   = "read_dynamodb"
  role   = "${aws_iam_role.threat_intel_downloader.id}"
  policy = "${data.aws_iam_policy_document.read_write_dynamodb.json}"
}

// IAM Policy Doc: Allow lambda function to read/write data from DynamoDB
data "aws_iam_policy_document" "read_write_dynamodb" {
  statement {
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:GetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:PutItem",
    ]

    resources = [
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.prefix}_streamalert_threat_intel_downloader",
    ]
  }
}

// IAM role policy: Allow lambda function to read from parameter store
resource "aws_iam_role_policy" "read_api_creds_from_ssm" {
  name   = "read_ssm"
  role   = "${aws_iam_role.threat_intel_downloader.id}"
  policy = "${data.aws_iam_policy_document.read_api_creds_from_ssm.json}"
}

// IAM Policy Doc: Allow lambda function to read from parameter store
data "aws_iam_policy_document" "read_api_creds_from_ssm" {
  statement {
    effect = "Allow"

    actions = [
      "ssm:GetParameters",
    ]

    resources = [
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.parameter_name}",
    ]
  }
}

// TODO: double check is needed
// IAM Role Policy: Allow the Threat Intel Downloader function to publish sns (used for DLQ)
resource "aws_iam_role_policy" "theat_intel_downloader_publish_sns" {
  name   = "threat_intel_downloader_publish_sns_role_policy"
  role   = "${aws_iam_role.threat_intel_downloader.id}"
  policy = "${data.aws_iam_policy_document.theat_intel_downloader_publish_sns.json}"
}

// IAM Policy Doc: Allow the StreamAlert App function to publish sns (used for DLQ)
data "aws_iam_policy_document" "theat_intel_downloader_publish_sns" {
  statement {
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      "arn:aws:sns:${var.region}:${var.account_id}:${var.monitoring_sns_topic}",
    ]
  }
}
