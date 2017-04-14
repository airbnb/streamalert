// Rule Processor Execution Role
resource "aws_iam_role" "streamalert_rule_processor_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_rule_processor_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

// Allow the Rule Processor to send alerts to SNS
resource "aws_iam_role_policy" "streamalert_rule_processor_sns" {
  name = "${var.prefix}_${var.cluster}_streamalert_rule_processor_send_to_sns"
  role = "${aws_iam_role.streamalert_rule_processor_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:Publish",
        "sns:Subscribe"
      ],
      "Effect": "Allow",
      "Resource": "${aws_sns_topic.streamalert.arn}"
    }
  ]
}
EOF
}

// Alert Processor Execution Role
resource "aws_iam_role" "streamalert_alert_processor_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

// Allow the Alert Processor to decrypt secrets
resource "aws_iam_role_policy" "streamalert_alert_processor_kms" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_kms"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Effect": "Allow",
      "Resource": "${var.kms_key_arn}"
    }
  ]
}
EOF
}

// Allow the Alert Processor to write objects to S3
// Default s3 bucket created by this module.
resource "aws_iam_role_policy" "streamalert_alert_processor_s3" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_s3_default"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

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
      "Resource": [
        "${aws_s3_bucket.streamalerts.arn}/*"
      ]
    },
    {
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::${var.prefix}.streamalert.secrets/*"
      ]
    }
  ]
}
EOF
}

// Allow the Alert Processor to write cloudwatch logs
resource "aws_iam_role_policy" "streamalert_alert_processor_cloudwatch" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_cloudwatch"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

// Allow the Alert Processor to invoke Lambda
resource "aws_iam_role_policy" "streamalert_alert_processor_lambda" {
  name = "${var.prefix}_${var.cluster}_streamalert_alert_processor_lambda"
  role = "${aws_iam_role.streamalert_alert_processor_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
