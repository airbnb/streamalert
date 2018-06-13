variable "region" {}

variable "account_id" {}

variable "lambda_handler" {}

variable "lambda_function_arn" {}

variable "lambda_memory" {
  type    = "string"
  default = "128"
}

variable "lambda_timeout" {
  type    = "string"
  default = "120"
}

variable "filename" {
  type    = "string"
  default = "threat_intel_downloader.zip"
}

variable "lambda_log_level" {
  type    = "string"
  default = "info"
}

variable "enable_metrics" {
  default = false
}

variable "prefix" {
  type = "string"
}

variable "interval" {
  type    = "string"
  default = "rate(1 day)"
}

variable "table_rcu" {
  default = 10
}

variable "table_wcu" {
  default = 10
}

variable "parameter_name" {
  default = "threat_intel_downloader_api_creds"
  type    = "string"
}

variable "monitoring_sns_topic" {}

variable "ioc_filters" {}

variable "ioc_keys" {}

variable "ioc_types" {}

variable "excluded_sub_types" {}

variable "log_retention" {
  default = 14
}

variable "max_read_capacity" {
  default = 5
}

variable "min_read_capacity" {
  default = 5
}

variable "target_utilization" {
  default = 70
}
