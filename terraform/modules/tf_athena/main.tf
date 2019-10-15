// Lambda Function: Athena Parition Refresh
resource "aws_lambda_function" "athena_partition_refresh" {
  function_name = "${var.prefix}_streamalert_athena_partition_refresh"
  description   = "StreamAlert Athena Refresh"
  runtime       = "python3.7"
  role          = aws_iam_role.athena_partition_role.arn
  handler       = var.lambda_handler
  memory_size   = var.lambda_memory
  timeout       = var.lambda_timeout

  filename         = var.filename
  source_code_hash = filebase64sha256(var.filename)
  publish          = true

  // Maximum number of concurrent executions allowed
  reserved_concurrent_executions = var.concurrency_limit

  environment {
    variables = {
      LOGGER_LEVEL = var.lambda_log_level
    }
  }

  tags = {
    Name    = "StreamAlert"
    AltName = "Athena"
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

// Lambda Alias: Athena Function Production Alias
resource "aws_lambda_alias" "athena_partition_refresh_production" {
  name             = "production"
  description      = "Production StreamAlert Athena Parition Refresh Alias"
  function_name    = aws_lambda_function.athena_partition_refresh.arn
  function_version = aws_lambda_function.athena_partition_refresh.version
}

// SQS Queue: Athena Data Bucket Notificaitons
resource "aws_sqs_queue" "streamalert_athena_data_bucket_notifications" {
  name = var.queue_name

  # Enables SQS Long Polling: https://amzn.to/2wn10CR
  receive_wait_time_seconds = 10

  # The amount of time messages are hidden after being received from a consumer
  visibility_timeout_seconds = format("%d", var.lambda_timeout + 2)

  # Retain messages for one day
  message_retention_seconds = 86400

  # Enable server-side encryption of messages in the queue
  kms_master_key_id = aws_kms_key.sse.arn

  tags = {
    Name    = "StreamAlert"
    AltName = "Athena"
  }
}

// SQS Queue Policy: Allow data buckets to send SQS messages
resource "aws_sqs_queue_policy" "streamalert_athena_data_bucket_notifications" {
  queue_url = aws_sqs_queue.streamalert_athena_data_bucket_notifications.id
  policy    = data.aws_iam_policy_document.athena_data_bucket_sqs_sendmessage.json
}

resource "aws_lambda_event_source_mapping" "streamalert_athena_sqs_event_source" {
  event_source_arn = aws_sqs_queue.streamalert_athena_data_bucket_notifications.arn
  function_name    = "${aws_lambda_function.athena_partition_refresh.arn}:${aws_lambda_alias.athena_partition_refresh_production.name}"
}

// S3 Bucekt Notificaiton: Configure S3 to notify Lambda
resource "aws_s3_bucket_notification" "bucket_notification" {
  count  = length(var.athena_data_buckets)
  bucket = element(var.athena_data_buckets, count.index)

  queue {
    queue_arn = aws_sqs_queue.streamalert_athena_data_bucket_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.streamalert_athena_data_bucket_notifications]
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

// CloudWatch metric filters for the athena partition refresh function
// The split list is made up of: <filter_name>, <filter_pattern>, <value>
resource "aws_cloudwatch_log_metric_filter" "athena_partition_refresh_cw_metric_filters" {
  count          = length(var.athena_metric_filters)
  name           = element(split(",", var.athena_metric_filters[count.index]), 0)
  pattern        = element(split(",", var.athena_metric_filters[count.index]), 1)
  log_group_name = aws_cloudwatch_log_group.athena.name

  metric_transformation {
    name      = element(split(",", var.athena_metric_filters[count.index]), 0)
    namespace = var.namespace
    value     = element(split(",", var.athena_metric_filters[count.index]), 2)
  }
}
