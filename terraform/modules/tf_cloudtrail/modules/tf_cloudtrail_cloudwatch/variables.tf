variable "region" {
  type        = string
  description = "AWS region where the CloudWatch Logs resources should be created"
}

variable "prefix" {
  type        = string
  description = "Resource prefix namespace"
}

variable "cluster" {
  type        = string
  description = "Name of the cluster"
}

variable "cloudwatch_destination_arn" {
  type        = string
  description = "ARN of the CloudWatch Destination to forward logs to that are sent to a CloudWatch Logs Group"
}

variable "retention_in_days" {
  default     = 1
  description = "Days for which to retain logs in the CloudWatch Logs Group"
}

variable "exclude_home_region_events" {
  default     = false
  description = "Set to `true` to omit CloudTrail events logged in the 'home' region. This is useful when global CloudTrail is desired, and a CloudWatch Logs Group is used, but home events are already collected (e.g. via another CloudTrail)"
}
