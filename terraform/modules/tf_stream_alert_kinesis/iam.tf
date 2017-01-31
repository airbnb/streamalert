// Firehose S3 Role
resource "aws_iam_role" "stream_alert_kinesis_firehose" {
  name = "${var.firehose_name}_firehose_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

// Firehose S3 policy
resource "aws_iam_role_policy" "stream_alert_firehose_s3" {
  name = "write_to_s3_${var.firehose_name}"
  role = "${aws_iam_role.stream_alert_kinesis_firehose.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:PutObject"
      ],
      "Resource": [
        "${aws_s3_bucket.firehose_store.arn}",
        "${aws_s3_bucket.firehose_store.arn}/*"
      ]
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.firehose_log_group}:log-stream:*"
      ]
    }
  ]
}
EOF
}

// Provide the stream_alert_wo user access to the Kinesis Firehose
resource "aws_iam_user_policy" "stream_alert_firehose_wo" {
  name = "${var.username}_firehose_wo"
  user = "${aws_iam_user.stream_alert_wo.name}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement" : [
    {
      "Effect": "Allow",
      "Action": [
        "firehose:Describe*",
        "firehose:List*",
        "firehose:PutRecord*"
      ],
      "Resource": [
        "${aws_kinesis_firehose_delivery_stream.stream_alert_firehose.arn}"
      ]
    }
  ]
}
EOF
}

// Provide the stream_alert_wo user access to the Kinesis Stream
resource "aws_iam_user_policy" "stream_alert_stream_wo" {
  name = "${var.username}_kinesis_wo"
  user = "${aws_iam_user.stream_alert_wo.name}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement" : [
    {
      "Action": [
        "kinesis:PutRecord*",
        "kinesis:DescribeStream",
        "kinesis:ListStreams"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_kinesis_stream.stream_alert_stream.arn}"
      ]
    }
  ]
}
EOF
}
