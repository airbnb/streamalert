variable "account_id" {}

variable "buffer_size" {
  default = 5
}

variable "buffer_interval" {
  default = 300
}

variable "cloudwatch_log_group" {
  default = "/aws/kinesisfirehose/stream_alert"
}

variable "compression_format" {
  default = "Snappy"
}

variable "logs" {
  type = "list"
}

variable "prefix" {}

variable "region" {}

variable "s3_bucket_name" {}

variable "s3_logging_bucket" {}
