// Policy for S3 bucket
data "aws_iam_policy_document" "athena_results_bucket" {
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
      "arn:aws:s3:::${var.results_bucket}",
      "arn:aws:s3:::${var.results_bucket}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

// S3 Bucket: Athena Query Results and Metastore Bucket
resource "aws_s3_bucket" "athena_results_bucket" {
  bucket        = var.results_bucket
  acl           = "private"
  policy        = data.aws_iam_policy_document.athena_results_bucket.json
  force_destroy = false

  tags = {
    Name    = "StreamAlert"
    AltName = "Athena"
  }

  versioning {
    enabled = true
  }

  logging {
    target_bucket = var.s3_logging_bucket
    target_prefix = "${var.results_bucket}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = var.kms_key_id
      }
    }
  }
}

// Athena Database: streamalert
resource "aws_athena_database" "streamalert" {
  name   = var.database_name
  bucket = aws_s3_bucket.athena_results_bucket.bucket
}

// Log Retention Policy
resource "aws_cloudwatch_log_group" "athena" {
  name              = "/aws/lambda/${aws_lambda_function.athena_partition_refresh.function_name}"
  retention_in_days = 14

  tags = {
    Name    = "StreamAlert"
    AltName = "Athena"
  }
}
