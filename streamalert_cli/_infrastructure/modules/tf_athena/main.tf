// Athena Database: streamalert
resource "aws_athena_database" "streamalert" {
  name   = var.database_name
  bucket = aws_s3_bucket.athena_results_bucket.bucket
}

// S3 Bucket: Athena Query Results and Metastore Bucket
resource "aws_s3_bucket" "athena_results_bucket" {
  bucket        = var.results_bucket
  acl           = "private"
  policy        = data.aws_iam_policy_document.athena_results_bucket.json
  force_destroy = false

  tags = {
    Name         = "StreamAlert"
    Subcomponent = "AthenaPartitioner"
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

// SQS Queue: Athena Data Bucket Notificaitons
resource "aws_sqs_queue" "data_bucket_notifications" {
  name = var.queue_name

  # Enables SQS Long Polling: https://amzn.to/2wn10CR
  receive_wait_time_seconds = 10

  # The amount of time messages are hidden after being received from a consumer
  visibility_timeout_seconds = (var.lambda_timeout + 2)

  # Retain messages for one day
  message_retention_seconds = 86400

  # Enable server-side encryption of messages in the queue
  kms_master_key_id = aws_kms_key.sse.arn

  tags = {
    Name         = "StreamAlert"
    Subcomponent = "AthenaPartitioner"
  }
}

// SQS Queue Policy: Allow data buckets to send SQS messages
resource "aws_sqs_queue_policy" "data_bucket_notifications" {
  queue_url = aws_sqs_queue.data_bucket_notifications.id
  policy    = data.aws_iam_policy_document.data_bucket_sqs.json
}

resource "aws_lambda_event_source_mapping" "athena_sqs" {
  event_source_arn = aws_sqs_queue.data_bucket_notifications.arn
  function_name    = var.function_alias_arn
}

// S3 Bucekt Notificaiton: Configure S3 to notify Lambda
resource "aws_s3_bucket_notification" "bucket_notification" {
  count  = length(var.athena_data_buckets)
  bucket = element(var.athena_data_buckets, count.index)

  queue {
    queue_arn = aws_sqs_queue.data_bucket_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.data_bucket_notifications]
}
