// Firehose S3 Role
resource "aws_iam_role" "stream_alert_kinesis_firehose" {
  name = "${var.firehose_name}_firehose_role"

  assume_role_policy = "${data.aws_iam_policy_document.firehose_assume_role_policy.json}"
}

data "aws_iam_policy_document" "firehose_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

// Firehose S3 policy
resource "aws_iam_role_policy" "stream_alert_firehose_s3" {
  name = "write_to_s3_${var.firehose_name}"
  role = "${aws_iam_role.stream_alert_kinesis_firehose.id}"

  policy = "${data.aws_iam_policy_document.firehose_s3.json}"
}

data "aws_iam_policy_document" "firehose_s3" {
  statement {
    effect = "Allow"

    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.firehose_store.arn}",
      "${aws_s3_bucket.firehose_store.arn}/*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.firehose_log_group}:log-stream:*",
    ]
  }
}

// Provide the stream_alert_wo user access to the Kinesis Firehose
resource "aws_iam_user_policy" "stream_alert_firehose_wo" {
  name = "${var.username}_firehose_wo"
  user = "${aws_iam_user.stream_alert_wo.name}"

  policy = "${data.aws_iam_policy_document.firehose_user_wo.json}"
}

data "aws_iam_policy_document" "firehose_user_wo" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:Describe*",
      "firehose:List*",
      "firehose:PutRecord*",
    ]

    resources = [
      "${aws_kinesis_firehose_delivery_stream.stream_alert_firehose.arn}",
    ]
  }
}

// Provide the stream_alert_wo user access to the Kinesis Stream
resource "aws_iam_user_policy" "stream_alert_stream_wo" {
  name = "${var.username}_kinesis_wo"
  user = "${aws_iam_user.stream_alert_wo.name}"

  policy = "${data.aws_iam_policy_document.stream_user_wo.json}"
}

data "aws_iam_policy_document" "stream_user_wo" {
  statement {
    effect = "Allow"

    actions = [
      "kinesis:PutRecord*",
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
    ]

    resources = [
      "${aws_kinesis_stream.stream_alert_stream.arn}",
    ]
  }
}
