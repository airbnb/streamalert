variable "metric_name" {
  description = "Name to assign to the custom metric being created"
  type        = string
}

variable "metric_value" {
  description = "The value that should be published to the metric"
  type        = string
}

variable "metric_default_value" {
  description = "The value to emit when a filter pattern does not match a log event."
  default     = 0
}

// See: https://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/FilterAndPatternSyntax.html
variable "metric_pattern" {
  description = "A valid CloudWatch Logs filter pattern for extracting metric data out of ingested log events"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch Log Group name to which the filter should be applied"
  type        = string
}
