// AWS Firehose Stream
resource "aws_kinesis_firehose_delivery_stream" "stream_alert_data" {
  count       = "${length(var.logs)}"
  name        = "streamalert_data_${element(var.logs, count.index)}"
  destination = "s3"

  s3_configuration {
    role_arn           = "${aws_iam_role.stream_alert_kinesis_firehose.arn}"
    bucket_arn         = "arn:aws:s3:::${var.s3_bucket_name}"
    prefix             = "${element(var.logs, count.index)}/"
    buffer_size        = "${var.buffer_size}"
    buffer_interval    = "${var.buffer_interval}"
    compression_format = "${var.compression_format}"
  }
}

resource "aws_s3_bucket" "stream_alert_data" {
  bucket        = "${var.s3_bucket_name}"
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${var.s3_logging_bucket}"
    target_prefix = "${var.s3_bucket_name}/"
  }

  tags {
    Name = "${var.s3_bucket_name}"
  }
}
