variable "account_id" {
  description = "12-digit AWS Account ID"
}

variable "region" {
  description = "AWS region identifier"
}

variable "prefix" {
  description = "Prefix for resource names"
}

variable "role_id" {
  description = "Alert processor IAM Role ID"
}

variable "kms_key_arn" {
  description = "KMS key ARN used for encrypting output secrets"
}

variable "output_lambda_functions" {
  type        = "list"
  default     = []
  description = "Optional list of configured Lambda outputs (function names)"
}

variable "output_s3_buckets" {
  type        = "list"
  default     = []
  description = "Optional list of configured S3 bucket outputs (bucket names)"
}

variable "output_sns_topics" {
  type        = "list"
  default     = []
  description = "Optional list of configured SNS outputs (topic names)"
}

variable "output_sqs_queues" {
  type        = "list"
  default     = []
  description = "Optional list of configured SQS outputs (queue names)"
}
