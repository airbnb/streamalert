variable "function_role_id" {
  description = "Classifier function IAM Role ID, exported from the tf_lambda module"
}

variable "function_alias_arn" {
  description = "Classifier function alias arn, exported from the tf_lambda module"
}

variable "function_name" {
  description = "Classifier function name, exported from the tf_lambda module"
}

variable "threat_intel_enabled" {
  default = false
}

variable "dynamodb_table_name" {
  default = "streamalert_threat_intel_ioc_table"
}

variable "rules_table_arn" {
  description = "ARN of the rules table for reading rule staging information"
}

variable "classifier_sqs_queue_arn" {
  description = "ARN of the SQS queue to which classified logs should be sent"
}
