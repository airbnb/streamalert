/*
// Rule Processor Execution Role
*/
resource "aws_iam_role" "streamalert_rule_processor_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_rule_processor_role"

  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

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

// Policy: Allow the Rule Processor to send alerts to SNS
resource "aws_iam_role_policy" "streamalert_rule_processor_sns" {
  name = "${var.prefix}_${var.cluster}_streamalert_rule_processor_send_to_sns"
  role = "${aws_iam_role.streamalert_rule_processor_role.id}"

  policy = "${data.aws_iam_policy_document.rule_processor_sns.json}"
}

data "aws_iam_policy_document" "rule_processor_sns" {
  statement {
    effect = "Allow"

    actions = [
      "sns:Publish",
      "sns:Subscribe",
    ]

    resources = [
      "${aws_sns_topic.streamalert.arn}",
    ]
  }
}

/*
// Alert Processor Execution Role
*/
resource "aws_iam_role" "streamalert_alert_processor_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_role"

  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

// Policy: Allow the Alert Processor to decrypt secrets
resource "aws_iam_role_policy" "streamalert_alert_processor_kms" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_kms"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.rule_processor_kms_decrypt.json}"
}

data "aws_iam_policy_document" "rule_processor_kms_decrypt" {
  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [
      "${var.kms_key_arn}",
    ]
  }
}

// Policy: Allow the Alert Processor to write objects to S3.
//         The default S3 bucket is also created by this module.
resource "aws_iam_role_policy" "streamalert_alert_processor_s3" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_s3_default"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_s3.json}"
}

data "aws_iam_policy_document" "alert_processor_s3" {
  statement {
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:ListBucket",
    ]

    resources = [
      "${aws_s3_bucket.streamalerts.arn}/*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:GetObject",
    ]

    resources = [
      "arn:aws:s3:::${var.prefix}.streamalert.secrets/*",
    ]
  }
}

// Policy: Allow the Alert Processor to write cloudwatch logs
resource "aws_iam_role_policy" "streamalert_alert_processor_cloudwatch" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_cloudwatch"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_cloudwatch.json}"
}

data "aws_iam_policy_document" "alert_processor_cloudwatch" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "*",
    ]
  }
}

// Policy: Allow the Alert Processor to invoke Lambda functions
resource "aws_iam_role_policy" "streamalert_alert_processor_lambda" {
  count = "${length(var.output_lambda_functions)}"
  name  = "${var.prefix}_${var.cluster}_streamalert_alert_processor_lambda_${element(var.output_lambda_functions, count.index)}"
  role  = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:lambda:${var.region}:${var.account_id}:function:${element(var.output_lambda_functions, count.index)}"
    }
  ]
}
EOF
}

// Policy: Allow the Alert Processor to send to arbitrary S3 buckets as outputs
resource "aws_iam_role_policy" "streamalert_alert_processor_s3_outputs" {
  count = "${length(var.output_s3_buckets)}"
  name  = "${var.prefix}_${var.cluster}_streamalert_alert_processor_s3_output_${element(var.output_s3_buckets, count.index)}"
  role  = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::${element(var.output_s3_buckets, count.index)}"
    }
  ]
}
EOF
}

// Policy: Allow the Alert Processor to run in a VPC
resource "aws_iam_role_policy" "streamalert_alert_processor_vpc" {
  count = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  name  = "${var.prefix}_${var.cluster}_streamalert_alert_processor_vpc"
  role  = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_vpc.json}"
}

data "aws_iam_policy_document" "alert_processor_vpc" {
  count = "${var.alert_processor_vpc_enabled ? 1 : 0}"

  statement {
    effect = "Allow"

    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
    ]

    resources = [
      "*",
    ]
  }
}
