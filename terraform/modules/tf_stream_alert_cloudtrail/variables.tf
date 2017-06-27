variable "account_id" {
  type = "string"
}

variable "cluster" {
  type = "string"
}

variable "kinesis_arn" {
  type = "string"
}

variable "prefix" {
  type = "string"
}

variable "enable_logging" {
  default = true
}

variable "existing_trail" {
  default = false
}

variable "is_global_trail" {
  default = true
}

variable "s3_logging_bucket" {
  type = "string"
}

variable "event_pattern" {
  type = "string"
}
