variable "account_id" {}

variable "region" {}

variable "cluster_name" {}

variable "stream_name" {
  default = "stream_alert_stream"
}

variable "shards" {
  default = 1
}

variable "retention" {
  default = 24
}
