// IAM Role: Firehose Delivery Stream
resource "aws_iam_role" "stream_alert_kinesis_firehose" {
  name = "streamalert_firehose_role"

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
  name = "streamalert_firehose_write_data_to_s3"
  role = "${aws_iam_role.stream_alert_kinesis_firehose.id}"

  policy = "${data.aws_iam_policy_document.firehose_s3.json}"
}

// IAM Policy Document: Write data to S3
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
      "arn:aws:s3:::${var.s3_bucket_name}",
      "arn:aws:s3:::${var.s3_bucket_name}/*",
    ]
  }
}

// IAM Policy: Write logs to CloudWatch
resource "aws_iam_role_policy" "stream_alert_firehose_cloudwatch" {
  name = "streamalert_firehose_write_data_to_cloudwatch"
  role = "${aws_iam_role.stream_alert_kinesis_firehose.id}"

  policy = "${data.aws_iam_policy_document.firehose_cloudwatch.json}"
}

// IAM Policy Document: Write logs to CloudWatch
data "aws_iam_policy_document" "firehose_cloudwatch" {
  statement {
    effect = "Allow"

    actions = [
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.cloudwatch_log_group}:log-stream:*",
    ]
  }
}
