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

variable "account_ids" {
  type = list(string)
}

variable "enable_kinesis" {
  default = true
}

variable "enable_logging" {
  default = true
}

variable "event_pattern" {
  type    = string
  default = ""
}

variable "existing_trail" {
  default = false
}

variable "is_global_trail" {
  default = true
}

variable "kinesis_arn" {
  type    = string
  default = ""
}

variable "s3_logging_bucket" {
  type = string
}

variable "cloudwatch_destination_arn" {
  default = ""
}

variable "send_to_cloudwatch" {
  default = false
}

variable "exclude_home_region_events" {
  default = false
}
