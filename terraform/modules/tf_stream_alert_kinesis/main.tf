// AWS Firehose Stream
resource "aws_kinesis_firehose_delivery_stream" "stream_alert_firehose" {
  name        = "${var.firehose_name}"
  destination = "s3"

  s3_configuration {
    role_arn   = "${aws_iam_role.stream_alert_kinesis_firehose.arn}"
    bucket_arn = "${aws_s3_bucket.firehose_store.arn}"
  }
}

// AWS Kinesis Stream
resource "aws_kinesis_stream" "stream_alert_stream" {
  name             = "${var.stream_name}"
  shard_count      = "${element(var.stream_config, 0)}"
  retention_period = "${element(var.stream_config, 1)}"

  shard_level_metrics = [
    "IncomingBytes",
    "IncomingRecords",
    "OutgoingBytes",
    "OutgoingRecords",
    "WriteProvisionedThroughputExceeded",
    "ReadProvisionedThroughputExceeded",
    "IteratorAgeMilliseconds",
  ]

  tags {
    Name    = "StreamAlert"
    Cluster = "${var.cluster_name}"
  }
}

resource "aws_s3_bucket" "firehose_store" {
  bucket        = "${var.firehose_s3_bucket_name}"
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  tags {
    Name    = "StreamAlert"
    Cluster = "${var.cluster_name}"
  }
}
