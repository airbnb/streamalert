variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "cloudwatch_log_group" {
  type    = string
  default = "/aws/kinesisfirehose/streamalert"
}

variable "s3_bucket_name" {
  type = string
}

variable "s3_logging_bucket" {
  type = string
}

variable "kms_key_id" {
  type = string
}
