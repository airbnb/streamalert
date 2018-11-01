variable "bucket_id" {}

variable "enable_events" {
  default = true
}

variable "filter_prefix" {
  default = ""
}

variable "filter_suffix" {
  default = ""
}

variable "lambda_function_alias_arn" {}

variable "lambda_role_id" {}

variable "notification_id" {}
