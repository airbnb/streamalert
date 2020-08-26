// IAM Role: Firehose Delivery Stream
resource "aws_iam_role" "streamalert_kinesis_firehose" {
  name               = "${var.prefix}_firehose_data_delivery"
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
  name   = "WriteDataToS3"
  role   = aws_iam_role.streamalert_kinesis_firehose.id
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
      "arn:aws:s3:::${var.s3_bucket_name}",
      "arn:aws:s3:::${var.s3_bucket_name}/*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]

    resources = ["arn:aws:kms:${var.region}:${var.account_id}:key/${var.kms_key_id}"]
  }
}

// IAM Policy: Write logs to CloudWatch
resource "aws_iam_role_policy" "streamalert_firehose_cloudwatch" {
  name   = "WriteDataToCloudWatch"
  role   = aws_iam_role.streamalert_kinesis_firehose.id
  policy = data.aws_iam_policy_document.firehose_cloudwatch.json
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

// IAM Policy: Interact with the Glue Catalog
resource "aws_iam_role_policy" "streamalert_firehose_glue" {
  name = "streamalert_firehose_read_glue_catalog"
  role = aws_iam_role.streamalert_kinesis_firehose.id

  policy = data.aws_iam_policy_document.firehose_glue_catalog.json
}

// IAM Policy Document: Interact with the Glue Catalog
data "aws_iam_policy_document" "firehose_glue_catalog" {
  statement {
    effect = "Allow"

    actions = [
      "glue:GetTable*"
    ]

    resources = ["*"]
  }
}
