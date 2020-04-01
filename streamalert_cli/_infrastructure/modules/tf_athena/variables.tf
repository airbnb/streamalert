variable "account_id" {
  type = string
}

variable "prefix" {
  type = string
}

variable "function_role_id" {
  description = "Athena Partitioner function IAM Role ID, exported from the tf_lambda module"
}

variable "function_alias_arn" {
  description = "Athena Partitioner function alias arn, exported from the tf_lambda module"
}

variable "function_name" {
  description = "Athena Partitioner function name, exported from the tf_lambda module"
}

variable "athena_data_buckets" {
  type = list(string)
}

variable "results_bucket" {
  type = string
}

variable "kms_key_id" {
  type = string
}

variable "s3_logging_bucket" {
  type = string
}

variable "database_name" {
  type = string
}

variable "queue_name" {
  type = string
}

variable "lambda_timeout" {
  type = number
}
