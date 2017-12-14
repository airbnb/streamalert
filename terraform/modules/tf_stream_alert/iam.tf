// IAM Role: Rule Processor Execution Role
resource "aws_iam_role" "streamalert_rule_processor_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_rule_processor_role"

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

// IAM Role Policy: Allow the Rule Processor to write CloudWatch logs
resource "aws_iam_role_policy" "streamalert_rule_processor_cloudwatch" {
  name = "CloudwatchWriteLogs"
  role = "${aws_iam_role.streamalert_rule_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_cloudwatch.json}"
}

// IAM Role Policy: Allow the Rule Processor to invoke the Alert Processor
resource "aws_iam_role_policy" "streamalert_rule_processor_lambda" {
  name = "LambdaInvokeAlertProcessor"
  role = "${aws_iam_role.streamalert_rule_processor_role.id}"

  policy = "${data.aws_iam_policy_document.rule_processor_invoke_alert_proc.json}"
}

// IAM Policy Doc: Allow the Rule Processor to invoke the Alert Processor
data "aws_iam_policy_document" "rule_processor_invoke_alert_proc" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    # Use interpolation because of the different VPC/non vpc resources
    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_${var.cluster}_streamalert_alert_processor",
    ]
  }
}

// IAM Role Policy: Allow the Rule Processor to put data on Firehose
resource "aws_iam_role_policy" "streamalert_rule_processor_firehose" {
  name = "FirehoseWriteData"
  role = "${aws_iam_role.streamalert_rule_processor_role.id}"

  policy = "${data.aws_iam_policy_document.streamalert_rule_processor_firehose.json}"
}

// IAM Policy Doc: Allow the Rule Processor to PutRecord* on any StreamAlert Firehose
data "aws_iam_policy_document" "streamalert_rule_processor_firehose" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:PutRecord*",
      "firehose:DescribeDeliveryStream",
      "firehose:ListDeliveryStreams",
    ]

    resources = [
      "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/streamalert_data_*",
    ]
  }
}

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
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.dynamodb_ioc_table}",
    ]
  }
}

// IAM Role: Alert Processor Execution Role
resource "aws_iam_role" "streamalert_alert_processor_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_role"

  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

// IAM Role Policy: Allow the Alert Processor to decrypt secrets
resource "aws_iam_role_policy" "streamalert_alert_processor_kms" {
  name = "KmsDecryptSecrets"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.rule_processor_kms_decrypt.json}"
}

// IAM Policy Doc: KMS key permissions for decryption
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

// IAM Role Policy: Allow the Alert Processor to write objects to S3.
//                  The default S3 bucket is also created by this module.
resource "aws_iam_role_policy" "streamalert_alert_processor_s3" {
  name = "S3WriteAlertsDefault"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_s3.json}"
}

// IAM Policy Doc: Allow fetching of secrets and putting of alerts
data "aws_iam_policy_document" "alert_processor_s3" {
  statement {
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${var.prefix}.streamalerts/*",
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

// IAM Role Policy: Allow the Alert Processor to write CloudWatch logs
resource "aws_iam_role_policy" "streamalert_alert_processor_cloudwatch" {
  name = "CloudwatchWriteLogs"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_cloudwatch.json}"
}

// IAM Policy Doc: Allow creating log groups and events in any CloudWatch stream
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

// IAM Role Policy: Allow the Alert Processor to invoke configured Lambda functions
resource "aws_iam_role_policy" "streamalert_alert_processor_lambda" {
  count = "${length(var.output_lambda_functions)}"
  name  = "LambdaInvoke${count.index}"
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
      "Resource": "arn:aws:lambda:${var.region}:${var.account_id}:function:${element(
        split(":", element(var.output_lambda_functions, count.index)), 0)}"
    }
  ]
}
EOF
}

// IAM Role Policy: Allow the Alert Processor to send to arbitrary S3 buckets as outputs
resource "aws_iam_role_policy" "streamalert_alert_processor_s3_outputs" {
  count = "${length(var.output_s3_buckets)}"
  name  = "S3PutObject${count.index}"
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

// IAM Role Policy: Allow the Alert Processor to write alerts to Firehose
resource "aws_iam_role_policy" "streamalert_alert_processor_firehose" {
  name = "FirehoseWriteAlerts"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = "${data.aws_iam_policy_document.alert_processor_firehose.json}"
}

// IAM Policy Doc: Allow the Alert Processor to Put data to the default Firehose
data "aws_iam_policy_document" "alert_processor_firehose" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:Put*",
    ]

    resources = [
      "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/${var.prefix}_streamalert_alert_delivery",
    ]
  }
}

// IAM Role Policy: Allow the Alert Processor to run in a VPC
resource "aws_iam_role_policy" "streamalert_alert_processor_vpc" {
  count = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  name  = "RunInVPC"
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
