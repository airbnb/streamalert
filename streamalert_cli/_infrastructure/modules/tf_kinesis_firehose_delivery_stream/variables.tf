
variable "stream_name" {
  type        = string
  description = "Fully qualified name to use for delivery stream"
}

variable "buffer_size" {
  default = 5
}

variable "buffer_interval" {
  default = 300
}

variable "file_format" {
  type        = string
  description = "Either parquet or json"
}

variable "role_arn" {
  type = string
}

variable "s3_bucket_name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "enable_alarm" {
  default     = false
  description = "Enable CloudWatch metric alarm for Firehose IncomingRecords count"
}

variable "alarm_threshold" {
  default     = 1000
  description = "Alarm if IncomingRecords count drops below this value in the specified period(s)"
}

variable "evaluation_periods" {
  default     = 1
  description = "Consecutive periods the records count threshold must be breached before triggering an alarm"
}

variable "period_seconds" {
  default     = 86400
  description = "Period over which to count the IncomingRecords (default: 86400 seconds [1 day])"
}

variable "alarm_actions" {
  type        = list(string)
  default     = []
  description = "Optional list of CloudWatch alarm actions (e.g. SNS topic ARNs)"
}

variable "glue_catalog_db_name" {
  type = string
}

variable "glue_catalog_table_name" {
  type = string
}

variable "schema" {
  type = list(tuple([string, string]))
}
