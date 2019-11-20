variable "batch_size" {
  default = 100
}

variable "kinesis_stream_arn" {
  type = string
}

variable "lambda_role_id" {
  type = string
}

variable "lambda_production_enabled" {
}

variable "lambda_function_alias_arn" {
  type = string
}
