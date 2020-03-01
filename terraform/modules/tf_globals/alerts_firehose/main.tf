locals {
  stream_name = "${var.prefix}_streamalert_alert_delivery"
}

resource "aws_kinesis_firehose_delivery_stream" "streamalerts" {
  name        = local.stream_name
  destination = var.store_format == "parquet" ? "extended_s3" : "s3"

  // AWS Firehose Stream for Alerts to S3 and saved in JSON format
  dynamic "s3_configuration" {
    for_each = var.store_format == "parquet" ? [] : [var.store_format]
    content {
      role_arn           = aws_iam_role.firehose.arn
      bucket_arn         = "arn:aws:s3:::${var.prefix}-streamalerts"
      prefix             = "alerts/"
      buffer_size        = var.buffer_size
      buffer_interval    = var.buffer_interval
      compression_format = "GZIP"
      kms_key_arn        = var.kms_key_arn

      cloudwatch_logging_options {
        enabled         = true
        log_group_name  = aws_cloudwatch_log_group.firehose.name
        log_stream_name = "S3Delivery"
      }
    }
  }

  // AWS Firehose Stream for Alerts to S3 and saved in Parquet format
  dynamic "extended_s3_configuration" {
    for_each = var.store_format == "parquet" ? [var.store_format] : []
    content {
      role_arn            = aws_iam_role.firehose.arn
      bucket_arn          = "arn:aws:s3:::${var.prefix}-streamalerts"
      prefix              = "alerts/dt=!{timestamp:yyyy-MM-dd-HH}/"
      error_output_prefix = "alerts/!{firehose:error-output-type}/"
      buffer_size         = var.buffer_size
      buffer_interval     = var.buffer_interval

      # The S3 destination's compression format must be set to UNCOMPRESSED
      # when data format conversion is enabled.
      compression_format = "UNCOMPRESSED"
      kms_key_arn        = var.kms_key_arn

      data_format_conversion_configuration {
        input_format_configuration {
          deserializer {
            # more resilient with log schemas that have nested JSON comparing to hive_json_ser_de
            open_x_json_ser_de {}
          }
        }
        output_format_configuration {
          serializer {
            parquet_ser_de {}
          }
        }
        schema_configuration {
          database_name = var.alerts_db_name
          role_arn      = aws_iam_role.firehose.arn
          table_name    = "alerts"
        }
      }

      cloudwatch_logging_options {
        enabled         = true
        log_group_name  = aws_cloudwatch_log_group.firehose.name
        log_stream_name = "S3Delivery"
      }
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
