variable "metric_name" {
  description = "Name to assign to the custom metric being created"
  type        = "string"
}

variable "metric_value" {
  description = "CloudWatch Log Group name to which the filter should be applied"
  type        = "string"
}

variable "metric_pattern" {
  description = "CloudWatch Log Group name to which the filter should be applied"
  type        = "string"
}

variable "log_group_name" {
  description = "CloudWatch Log Group name to which the filter should be applied"
  type        = "string"
}
