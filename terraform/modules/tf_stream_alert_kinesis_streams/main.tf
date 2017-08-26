// AWS Kinesis Stream
resource "aws_kinesis_stream" "stream_alert_stream" {
  name             = "${var.stream_name}"
  shard_count      = "${var.shards}"
  retention_period = "${var.retention}"

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
