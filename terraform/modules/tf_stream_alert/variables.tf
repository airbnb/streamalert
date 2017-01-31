variable "account_id" {}

variable "region" {}

variable "lambda_source_bucket_name" {}

variable "lambda_source_key" {}

variable "lambda_handler" {}

variable "lambda_function_prod_version" {}

variable "output_lambda_function_name" {}

variable "kms_key_arn" {}

variable "output_lambda_source_key" {}

variable "lambda_function_name" {
  default = "stream_alert_processor"
}

variable "lambda_timeout" {
  default = "10"
}

variable "lambda_memory" {
  default = "128"
}

variable "output_lambda_timeout" {
  default = "10"
}

variable "output_lambda_memory" {
  default = "128"
}
