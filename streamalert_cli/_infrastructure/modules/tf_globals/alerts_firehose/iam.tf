// IAM Role: Alert Firehose S3 Role
resource "aws_iam_role" "firehose" {
  name               = "${var.prefix}_firehose_alert_delivery"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume_role_policy.json

  tags = {
    Name = "StreamAlert"
  }
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
resource "aws_iam_role_policy" "streamalert_firehose_s3" {
  name   = "S3PutAlerts"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose_s3.json
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
      "arn:aws:s3:::${var.bucket_name}",
      "arn:aws:s3:::${var.bucket_name}/*",
    ]
  }
}

// IAM Policy: Interact with the Glue Catalog
resource "aws_iam_role_policy" "stream_alert_firehose_glue" {
  name = "streamalert_firehose_read_glue_catalog"
  role = aws_iam_role.firehose.id

  policy = data.aws_iam_policy_document.firehose_glue_catalog.json
}

// IAM Policy Document: Interact with the Glue Catalog
data "aws_iam_policy_document" "firehose_glue_catalog" {
  statement {
    effect = "Allow"

    actions = [
      "glue:GetTableVersions"
    ]

    resources = ["*"]
  }
}

// CloudWatch Log Stream: S3Delivery
resource "aws_cloudwatch_log_stream" "s3_delivery" {
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

// IAM Policy: Write logs to CloudWatch
resource "aws_iam_role_policy" "firehose_logging" {
  name   = "CloudWatchPutLogs"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose_cloudwatch.json
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
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/kinesisfirehose/${local.stream_name}:*",
    ]
  }
}
