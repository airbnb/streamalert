variable "account_id" {}

variable "cloudwatch_log_group" {
  default = "/aws/kinesisfirehose/stream_alert"
}

variable "prefix" {}

variable "region" {}

variable "s3_bucket_name" {}

variable "s3_logging_bucket" {}
