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
  default = "60"
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

variable "current_version" {
  type = "string"
}

variable "athena_data_buckets" {
  type = "list"
}

variable "prefix" {
  type = "string"
}

variable "refresh_interval" {
  type    = "string"
  default = "rate(10 minutes)"
}

variable "enable_metrics" {
  default = false
}

variable "athena_metric_filters" {
  type    = "list"
  default = []
}

variable "namespace" {
  type    = "string"
  default = "StreamAlert"
}
