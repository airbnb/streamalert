// Policy for S3 bucket
data "aws_iam_policy_document" "streamalert_data" {
  # Force SSL access only
  statement {
    sid = "ForceSSLOnlyAccess"

    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}",
      "arn:aws:s3:::${var.s3_bucket_name}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket" "streamalert_data" {
  bucket        = var.s3_bucket_name
  force_destroy = false
  tags = {
    Name = "StreamAlert"
  }
}

resource "aws_s3_bucket_acl" "streamalert_data" {
  bucket = aws_s3_bucket.streamalert_data.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "streamalert_data" {
  bucket = aws_s3_bucket.streamalert_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "streamalert_data" {
  bucket = aws_s3_bucket.streamalert_data.id
  target_bucket = var.s3_logging_bucket
  target_prefix = "${var.s3_bucket_name}/"
}

resource "aws_s3_bucket_policy" "streamalert_data" {
  bucket = aws_s3_bucket.streamalert_data.id
  policy = data.aws_iam_policy_document.streamalert_data.json
}

resource "aws_s3_bucket_server_side_encryption_configuration" "streamalert_data" {
  bucket = aws_s3_bucket.streamalert_data.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_id
      sse_algorithm     = "aws:kms"
    }
  }
}
