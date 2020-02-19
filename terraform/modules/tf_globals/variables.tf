variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "alerts_firehose_bucket_name" {
  type    = string
  default = ""
}

variable "alerts_firehose_buffer_size" {
  type    = number
  default = 128
}

variable "alerts_firehose_buffer_interval" {
  type    = number
  default = 300
}

variable "alerts_firehose_cloudwatch_log_retention" {
  type    = number
  default = 14
}

variable "alerts_firehose_compression_format" {
  type    = string
  default = "GZIP"
}

variable "alerts_table_read_capacity" {
  type    = number
  default = 5
}

variable "alerts_table_write_capacity" {
  type    = number
  default = 5
}

variable "enable_rule_staging" {
  default = false
}

variable "rules_table_read_capacity" {
  type    = number
  default = 5
}

variable "rules_table_write_capacity" {
  type    = number
  default = 5
}

variable "rules_engine_timeout" {
  default = 300
}

variable "sqs_use_prefix" {
  default = false
}
