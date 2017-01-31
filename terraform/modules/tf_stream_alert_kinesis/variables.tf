variable "account_id" {}

variable "region" {}

variable "username" {}

variable "cluster_name" {}

variable "firehose_s3_bucket_name" {}

variable "firehose_name" {
  default = "stream_alert_firehose"
}

variable "firehose_log_group" {
  default = "/aws/kinesisfirehose/stream_alert"
}

variable "stream_name" {
  default = "stream_alert_stream"
}

variable "stream_shards" {
  default = 2
}

variable "stream_retention" {
  default = 24
}
