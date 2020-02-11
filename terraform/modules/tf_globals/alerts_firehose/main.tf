// AWS Firehose Stream for Alerts to S3
resource "aws_kinesis_firehose_delivery_stream" "streamalerts" {
  name        = "${var.prefix}_streamalert_alert_delivery"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = "arn:aws:s3:::${var.prefix}.streamalerts"
    prefix              = "alerts/dt=!{timestamp:yyyy-MM-dd-HH}/"
    error_output_prefix = "alerts/!{firehose:error-output-type}/"
    buffer_size         = var.buffer_size
    buffer_interval     = var.buffer_interval
    compression_format  = "UNCOMPRESSED"
    kms_key_arn         = var.kms_key_arn

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
      log_group_name  = "/aws/kinesisfirehose/${var.prefix}_streamalert_alert_delivery"
      log_stream_name = "S3Delivery"
    }
  }

  tags = {
    Name = "StreamAlert"
  }
}
