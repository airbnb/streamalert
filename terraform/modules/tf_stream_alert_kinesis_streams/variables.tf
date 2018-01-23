variable "access_key_count" {
  default = 1
}

variable "account_id" {}

variable "cluster_name" {}

variable "create_user" {
  default = true
}

variable "trusted_accounts" {
  default = []
}

variable "prefix" {}

variable "region" {}

variable "retention" {
  default = 24
}

variable "stream_name" {
  default = "stream_alert_stream"
}

variable "shards" {
  default = 1
}

// Default values for shard_level_metrics
variable "shard_level_metrics" {
  type    = "list"
  default = []
}
