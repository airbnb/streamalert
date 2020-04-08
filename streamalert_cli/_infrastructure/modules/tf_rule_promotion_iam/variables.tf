variable "digest_sns_topic" {
  description = "SNS topic name to use for alert statistics digests"
}

variable "rules_table_arn" {
  description = "Rules DynamoDB Table arn, exported from the tf_globals module"
}

variable "role_id" {
  description = "Rule Promotion IAM Role ID, exported from the tf_lambda module"
}

variable "function_alias_arn" {
  description = "Rule Promotion function alias arn, exported from the tf_lambda module"
}

variable "function_name" {
  description = "Rule Promotion function name, exported from the tf_lambda module"
}

variable "send_digest_schedule_expression" {
  description = "Cron or rate expression to be used for scheduling the sending of the rule staging digest"
}

variable "athena_results_bucket_arn" {
  description = "S3 bucket arn to use for Athena search results"
}

variable "alerts_bucket" {
  description = "Name of S3 bucket where alerts are stored and queryable by Athena"
  type        = string
}

variable "s3_kms_key_arn" {
  description = "KMS key ARN used for server-side encryption"
}
