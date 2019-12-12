variable "primary_account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "cluster" {
  type = string
}

variable "s3_cross_account_ids" {
  type    = list(string)
  default = []
}

variable "enable_logging" {
  default = true
}

variable "retention_in_days" {
  default     = 1
  description = "Days for which to retain logs in the CloudWatch Logs Group. Default=1"
}

variable "is_global_trail" {
  default = true
}

variable "s3_logging_bucket" {
  type = string
}

variable "s3_bucket_name" {
  type = string
}

variable "s3_event_selector_type" {
  type    = string
  default = ""
}

variable "send_to_cloudwatch" {
  default = false
}

variable "cloudwatch_destination_arn" {
  type    = string
  default = ""
}

variable "exclude_home_region_events" {
  default = false
}
