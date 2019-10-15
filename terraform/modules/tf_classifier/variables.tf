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

variable "input_sns_topics" {
  description = "SNS topics to which the classifier function should subscribe"
  type        = list(string)
  default     = []
}

variable "classifier_sqs_queue_arn" {
  description = "ARN of the SQS queue to which classified logs should be sent"
}

variable "classifier_sqs_sse_kms_key_arn" {
  description = "ARN of the KMS key that handles server-side-encryption of classifier SQS frames"
}

variable "firehose_use_prefix" {
  description = "When true, prepends the StreamAlert prefix to the AWS Firehose permissions"
}
