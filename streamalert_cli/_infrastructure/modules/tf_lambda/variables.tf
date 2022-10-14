variable "function_name" {
  description = "Name of the Lambda function"
}

variable "description" {
  default     = ""
  description = "Description of the Lambda function"
}

variable "runtime" {
  default     = "python3.9"
  description = "Function runtime environment"
}

variable "layers" {
  type        = list(string)
  default     = []
  description = "List of Lambda Layer ARNs to use with this function"
}

variable "handler" {
  description = "Entry point for the function"
}

variable "memory_size_mb" {
  default     = 128
  description = "Memory allocated to the function. CPU and network are allocated proportionally."
}

variable "timeout_sec" {
  default     = 30
  description = "Maximum duration before execution is terminated"
}

variable "filename" {
  default     = "streamalert.zip"
  description = "Path to .zip deployment package"
}

variable "concurrency_limit" {
  default     = -1
  description = "Optional reserved concurrency. By default, there is no function-specific concurrency limit."
}

variable "environment_variables" {
  type        = map(string)
  description = "Map of environment variables available to the running Lambda function"
}

variable "vpc_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Optional list of VPC subnet IDs"
}

variable "vpc_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Optional list of security group IDs (for VPC)"
}

variable "default_tags" {
  type = map(string)

  default = {
    Name = "StreamAlert"
  }

  description = "The default tags to be associated with all applicable components"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Any additional tags to be associated with all applicable components"
}

variable "auto_publish_versions" {
  default     = true
  description = "Whether Terraform should automatically publish new versions of the function"
}

variable "alias_name" {
  default     = "production"
  description = "An alias with this name is automatically created which points to the current version"
}

variable "schedule_expression" {
  default     = ""
  description = "Optional rate() or cron() expression to schedule the Lambda function at regular intervals"
}

variable "lambda_input_event" {
  type        = map(string)
  default     = {}
  description = "Optional dictionary representing input to be encoded to json and passed to the Lambda function"
}

variable "log_retention_days" {
  default     = 14
  description = "CloudWatch logs for the Lambda function will be retained for this many days"
}

// ***** CloudWatch metric alarms *****

variable "alarm_actions" {
  type        = list(string)
  default     = []
  description = "Optional list of CloudWatch alarm actions (e.g. SNS topic ARNs)"
}

variable "errors_alarm_enabled" {
  default     = true
  description = "Enable CloudWatch metric alarm for invocation errors"
}

variable "errors_alarm_threshold" {
  default     = 0
  description = "Alarm if Lambda invocation errors exceed this value in the specified period(s)"
}

variable "errors_alarm_evaluation_periods" {
  default     = 1
  description = "Consecutive periods the errors threshold must be breached before triggering an alarm"
}

variable "errors_alarm_period_secs" {
  default     = 120
  description = "Period over which to count the number of invocation errors"
}

variable "throttles_alarm_enabled" {
  default     = true
  description = "Enable CloudWatch metric alarm for throttled executions"
}

variable "throttles_alarm_threshold" {
  default     = 0
  description = "Alarm if Lambda throttles exceed this value in the specified period(s)"
}

variable "throttles_alarm_evaluation_periods" {
  default     = 1
  description = "Consecutive periods the throttles threshold must be breached before triggering an alarm"
}

variable "throttles_alarm_period_secs" {
  default     = 120
  description = "Period over which to count the number of throttles"
}

variable "iterator_age_alarm_enabled" {
  default     = false
  description = "Enable IteratorAge alarm (applicable only for stream-based invocations like Kinesis)"
}

variable "iterator_age_alarm_threshold_ms" {
  default     = 3600000
  description = "Alarm if the Lambda IteratorAge (ms) exceeds this value in the specified period(s)"
}

variable "iterator_age_alarm_evaluation_periods" {
  default     = 1
  description = "Consecutive periods the IteratorAge threshold must be breached before triggering an alarm"
}

variable "iterator_age_alarm_period_secs" {
  default     = 120
  description = "Period over which to evaluate the maximum IteratorAge"
}

variable "input_sns_topics" {
  description = "SNS topics that are allowed to invoke this Lambda function"
  type        = list(string)
  default     = []
}
