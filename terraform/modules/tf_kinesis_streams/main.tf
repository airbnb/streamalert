// AWS Kinesis Stream
resource "aws_kinesis_stream" "streamalert_stream" {
  name             = var.stream_name
  shard_count      = var.shards
  retention_period = var.retention

  shard_level_metrics = var.shard_level_metrics

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}
