variable "access_key_count" {
  default = 1
}

variable "account_id" {}

variable "region" {}

variable "cluster_name" {}

variable "prefix" {}

variable "stream_name" {
  default = "stream_alert_stream"
}

variable "shards" {
  default = 1
}

variable "retention" {
  default = 24
}

// Default values for shard_level_metrics
variable "shard_level_metrics" {
  type    = "list"
  default = []
}