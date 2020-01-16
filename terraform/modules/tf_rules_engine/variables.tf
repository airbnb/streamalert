variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

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

variable "enable_rule_staging" {
  description = "Deploy rule staging resources if enabled"
  default     = false
}

variable "rules_table_arn" {
  description = "ARN of the rules table for reading rule staging information"
}

variable "classifier_sqs_queue_arn" {
  description = "ARN of the SQS queue to which classified logs should be sent"
}

variable "classifier_sqs_sse_kms_key_arn" {
  description = "URL of the SQS queue to which classified logs should be sent"
}

variable "sqs_record_batch_size" {
  description = "Number of records the Lambda function should read from the SQS queue each time (max=10)"
}
