variable "alarm_name" {
  description = "Name for the alarm being created"
  type        = string
}

variable "alarm_description" {
  description = "Description for the alarm being created"
  type        = string
}

variable "comparison_operator" {
  description = "Comparison operator to use for this alarm. Choices are: GreaterThanOrEqualToThreshold, GreaterThanThreshold, LessThanThreshold, or LessThanOrEqualToThreshold"
  type        = string
}

variable "evaluation_periods" {
  description = "Consecutive periods the metric threshold must be breached before triggering an alarm"
  type        = string
}

variable "metric_name" {
  description = "Name of the metric being evaluated for this alarm"
  type        = string
}

variable "period" {
  description = "Period over which to count the occurrences of this metric"
  type        = string
}

variable "statistic" {
  description = "CloudWatch metric statistic to use when evaluating this metric. Choices are: SampleCount, Average, Sum, Minimum, or Maximum"
  type        = string
}

variable "threshold" {
  description = "Alarm if number of occurrences of this metric exceed this value in the specified period(s)"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic arn to use for alarm actions"
  type        = string
}
