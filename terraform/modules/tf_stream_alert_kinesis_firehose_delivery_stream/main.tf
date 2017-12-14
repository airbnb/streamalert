// AWS Firehose Stream: StreamAlert Data
//
// This resource is broken out into its own module due to the way
// Terraform handles list interpolation on resources.
//
// This is a less destructive approach to creating all of the Streams.
resource "aws_kinesis_firehose_delivery_stream" "stream_alert_data" {
  name        = "streamalert_data_${var.log_name}"
  destination = "s3"

  s3_configuration {
    role_arn           = "${var.role_arn}"
    bucket_arn         = "arn:aws:s3:::${var.s3_bucket_name}"
    prefix             = "${var.log_name}/"
    buffer_size        = "${var.buffer_size}"
    buffer_interval    = "${var.buffer_interval}"
    compression_format = "${var.compression_format}"
  }
}
