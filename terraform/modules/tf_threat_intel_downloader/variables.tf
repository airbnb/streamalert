variable "region" {}

variable "account_id" {}

variable "lambda_handler" {
  type    = "string"
  default = "main.handler"
}

variable "lambda_memory" {
  type    = "string"
  default = "128"
}

variable "lambda_timeout" {
  type    = "string"
  default = "120"
}

variable "lambda_s3_bucket" {
  type = "string"
}

variable "lambda_s3_key" {
  type = "string"
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

variable "current_version" {
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
