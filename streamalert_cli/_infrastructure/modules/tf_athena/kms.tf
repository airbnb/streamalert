// KMS key: Server-Side Encryption for SQS
resource "aws_kms_key" "sse" {
  description         = "Athena SQS server-side encryption"
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.kms_sse.json

  tags = {
    Name         = "StreamAlert"
    Subcomponent = "AthenaPartitioner"
  }
}

resource "aws_kms_alias" "sse" {
  name          = "alias/${var.prefix}_streamalert_sqs_sse"
  target_key_id = aws_kms_key.sse.key_id
}

// Allow S3 to use the SSE key when publishing events to SQS
data "aws_iam_policy_document" "kms_sse" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowS3ToUseKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = ["*"]
  }
}
