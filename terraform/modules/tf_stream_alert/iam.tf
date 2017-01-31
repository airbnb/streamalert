// Lambda Function Role
resource "aws_iam_role" "stream_alert_lambda_role" {
  name = "${var.lambda_function_name}_role"

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

resource "aws_iam_role_policy" "stream_alert_lambda_sns" {
  name = "${var.lambda_function_name}_send_to_sns"
  role = "${aws_iam_role.stream_alert_lambda_role.id}"

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

resource "aws_iam_role" "stream_alert_output_lambda_role" {
  name = "${var.output_lambda_function_name}_role"

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

resource "aws_iam_role_policy" "stream_alert_output_lambda_kms" {
  name = "${var.output_lambda_function_name}_kms"
  role = "${aws_iam_role.stream_alert_output_lambda_role.id}"

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

resource "aws_iam_role_policy" "stream_alert_output_lambda_s3" {
  name = "${var.output_lambda_function_name}_s3_output"
  role = "${aws_iam_role.stream_alert_output_lambda_role.id}"

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
        "${aws_s3_bucket.stream_alert_output.arn}",
        "${aws_s3_bucket.stream_alert_output.arn}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "stream_alert_output_lambda_cloudwatch" {
  name = "${var.output_lambda_function_name}_cloudwatch"
  role = "${aws_iam_role.stream_alert_output_lambda_role.id}"
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