// IAM Role: Alert Firehose S3 Role
resource "aws_iam_role" "firehose" {
  name = "${var.prefix}_${var.cluster}_streamalert_delivery_firehose"

  assume_role_policy = "${data.aws_iam_policy_document.firehose_assume_role_policy.json}"
}

// IAM Policy: Service AssumeRole
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

// IAM Policy: Write data to S3
resource "aws_iam_role_policy" "stream_alert_firehose_s3" {
  name = "S3PutAlerts"
  role = "${aws_iam_role.firehose.id}"

  policy = "${data.aws_iam_policy_document.firehose_s3.json}"
}

// IAM Policy Document: Write data to S3
data "aws_iam_policy_document" "firehose_s3" {
  statement {
    effect = "Allow"

    # Ref: http://amzn.to/2u5t0hS
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${var.prefix}.streamalerts",
      "arn:aws:s3:::${var.prefix}.streamalerts/*",
    ]
  }
}

// CloudWatch Log Group: Firehose
resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${var.prefix}_${var.cluster}_streamalert_alert_delivery"
  retention_in_days = "${var.cloudwatch_log_retention}"
}

// CloudWatch Log Stream: S3Delivery
resource "aws_cloudwatch_log_stream" "s3_delivery" {
  name           = "S3Delivery"
  log_group_name = "${aws_cloudwatch_log_group.firehose.name}"
}

// IAM Policy: Write logs to CloudWatch
resource "aws_iam_role_policy" "firehose_logging" {
  name = "CloudWatchPutLogs"
  role = "${aws_iam_role.firehose.id}"

  policy = "${data.aws_iam_policy_document.firehose_cloudwatch.json}"
}

data "aws_iam_policy_document" "firehose_cloudwatch" {
  statement {
    effect = "Allow"

    actions = [
      "logs:DescribeLogStreams",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/kinesisfirehose/${var.prefix}_${var.cluster}_streamalert_alert_delivery:*",
    ]
  }
}

// AWS Firehose Stream for Alerts
resource "aws_kinesis_firehose_delivery_stream" "stream_alerts" {
  name        = "${var.prefix}_${var.cluster}_streamalert_alert_delivery"
  destination = "s3"

  s3_configuration {
    role_arn           = "${aws_iam_role.firehose.arn}"
    bucket_arn         = "arn:aws:s3:::${var.prefix}.streamalerts"
    prefix             = "alerts/"
    buffer_size        = "${var.firehose_buffer_size}"
    buffer_interval    = "${var.firehose_buffer_interval}"
    compression_format = "${var.firehose_compression_format}"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/${var.prefix}_${var.cluster}_streamalert_alert_delivery"
      log_stream_name = "S3Delivery"
    }
  }
}
