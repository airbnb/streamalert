// AWS Firehose Stream dedicated to deliver Artifacts
// This firehose will only convert and save Artifacts in Parquet format in the S3 bucket to take the
// performance gain from Parquet format.
locals {
  s3_path_prefix = "parquet/${var.glue_catalog_table_name}"
}

locals {
  data_location = "s3://${var.s3_bucket_name}/${local.s3_path_prefix}"
}

resource "aws_kinesis_firehose_delivery_stream" "streamalert_artifacts" {
  name        = var.stream_name
  destination = "extended_s3"

  // AWS Firehose Stream for Artifacts will only support Parquet format
  extended_s3_configuration {
    role_arn            = aws_iam_role.streamalert_kinesis_firehose.arn
    bucket_arn          = "arn:aws:s3:::${var.s3_bucket_name}"
    prefix              = "${local.s3_path_prefix}/dt=!{timestamp:yyyy-MM-dd-HH}/"
    error_output_prefix = "${local.s3_path_prefix}/!{firehose:error-output-type}/"
    buffer_size         = var.buffer_size
    buffer_interval     = var.buffer_interval

    # The S3 destination's compression format must be set to UNCOMPRESSED
    # when data format conversion is enabled.
    compression_format = "UNCOMPRESSED"
    kms_key_arn        = var.kms_key_arn

    data_format_conversion_configuration {
      input_format_configuration {
        deserializer {
          # # more resilient with log schemas that have nested JSON comparing to hive_json_ser_de
          open_x_json_ser_de {}
        }
      }
      output_format_configuration {
        serializer {
          parquet_ser_de {}
        }
      }
      schema_configuration {
        database_name = aws_glue_catalog_table.artifacts.database_name
        role_arn      = aws_iam_role.streamalert_kinesis_firehose.arn
        table_name    = aws_glue_catalog_table.artifacts.name
      }
    }
  }

  tags = {
    Name = "StreamAlert"
  }
}

// Artifacts Athena table
resource "aws_glue_catalog_table" "artifacts" {
  name          = var.glue_catalog_table_name
  database_name = var.glue_catalog_db_name

  table_type = "EXTERNAL_TABLE"

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = local.data_location
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      name                  = "parque_ser_de"
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
      parameters = {
        ser_de_params_key   = "serialization.format"
        ser_de_params_value = "1"
      }
    }

    dynamic "columns" {
      for_each = var.schema
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}
