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
  description = "Rules DynamoDB Table arn exported from tf_stream_alert_globals"
}

variable "role_id" {
  description = "Rule Promotion IAM Role ID"
}

variable "athena_results_bucket_arn" {
  description = "S3 bucket arn to use for Athena search results"
}
