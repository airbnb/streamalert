variable "stats_publisher_state_name" {
  default = "Name of stats publisher state to be used when storing in SSM"
}

variable "stats_publisher_state_value" {
  default = "Value of stats publisher state which should be encoded JSON"
}

variable "digest_sns_topic" {
  description = "SNS topic name to use for alert statistics digests"
}

variable "rules_table_arn" {
  description = "Rules DynamoDB Table arn, exported from the tf_stream_alert_globals module"
}

variable "role_id" {
  description = "Rule Promotion IAM Role ID, exported from the tf_lambda module"
}

variable "function_alias_arn" {
  description = "Rule Promotion function alias arn, exported from the tf_lambda module"
}

variable "send_digest_schedule_expression" {
  description = "Cron or rate expression to be used for scheduling the sending of the rule staging digest"
}

variable "athena_results_bucket_arn" {
  description = "S3 bucket arn to use for Athena search results"
}

variable "athena_data_buckets" {
  description = "List of S3 buckets where Athena data is stored"
  type        = "list"
}
