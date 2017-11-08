variable "batch_size" {
  default = 100
}

variable "kinesis_stream_arn" {}

variable "lambda_role_id" {}

variable "lambda_production_enabled" {}

variable "lambda_function_arn" {}

variable "role_policy_prefix" {}
