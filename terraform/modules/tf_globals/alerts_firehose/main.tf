locals {
  stream_name = "${var.prefix}_streamalert_alert_delivery"
}

// AWS Firehose Stream for Alerts to S3
resource "aws_kinesis_firehose_delivery_stream" "streamalerts" {
  name        = local.stream_name
  destination = "s3"

  s3_configuration {
    role_arn           = aws_iam_role.firehose.arn
    bucket_arn         = "arn:aws:s3:::${var.bucket_name}"
    prefix             = "alerts/"
    buffer_size        = var.buffer_size
    buffer_interval    = var.buffer_interval
    compression_format = var.compression_format
    kms_key_arn        = var.kms_key_arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = "S3Delivery"
    }
  }

  tags = {
    Name = "StreamAlert"
  }
}

// CloudWatch Log Group: Firehose
resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${local.stream_name}"
  retention_in_days = var.cloudwatch_log_retention

  tags = {
    Name = "StreamAlert"
  }
}
