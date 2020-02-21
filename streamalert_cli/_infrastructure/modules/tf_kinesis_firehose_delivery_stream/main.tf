// AWS Firehose Stream: StreamAlert Data
//
// This resource is broken out into its own module due to the way
// Terraform handles list interpolation on resources.
//
// This is a less destructive approach to creating all of the Streams.
resource "aws_kinesis_firehose_delivery_stream" "streamalert_data" {
  name        = "${var.use_prefix ? "${var.prefix}_" : ""}streamalert_data_${var.log_name}"
  destination = "s3"

  s3_configuration {
    role_arn           = var.role_arn
    bucket_arn         = "arn:aws:s3:::${var.s3_bucket_name}"
    prefix             = "${var.log_name}/"
    buffer_size        = var.buffer_size
    buffer_interval    = var.buffer_interval
    compression_format = var.compression_format
    kms_key_arn        = var.kms_key_arn
  }

  tags = {
    Name = "StreamAlert"
  }
}

// AWS CloudWatch Metric Alarm for this Firehose
resource "aws_cloudwatch_metric_alarm" "firehose_records_alarm" {
  count               = var.enable_alarm ? 1 : 0
  alarm_name          = "${aws_kinesis_firehose_delivery_stream.streamalert_data.name}_record_count"
  namespace           = "AWS/Firehose"
  metric_name         = "IncomingRecords"
  statistic           = "Sum"
  comparison_operator = "LessThanThreshold"
  threshold           = var.alarm_threshold
  evaluation_periods  = var.evaluation_periods
  period              = var.period_seconds
  alarm_description   = "StreamAlert Firehose record count less than expected threshold: ${var.log_name}"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DeliveryStreamName = aws_kinesis_firehose_delivery_stream.streamalert_data.name
  }

  tags = {
    Name = "StreamAlert"
  }
}
