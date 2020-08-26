// IAM Role: Artifacts Firehose Delivery Stream permissions
resource "aws_iam_role" "streamalert_kinesis_firehose" {
  name               = "${var.prefix}_firehose_artifacts_delivery"
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
  name   = "WriteArtifactsToS3"
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

    resources = [var.kms_key_arn]
  }
}

// IAM Policy: Interact with the Glue Catalog
resource "aws_iam_role_policy" "streamalert_firehose_glue" {
  name = "FirehoseReadGlueCatalog"
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
