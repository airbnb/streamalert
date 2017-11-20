variable "account_ids" {
  type = "list"
}

variable "cluster" {
  type = "string"
}

variable "enable_kinesis" {
  default = true
}

variable "enable_logging" {
  default = true
}

variable "event_pattern" {
  type    = "string"
  default = ""
}

variable "existing_trail" {
  default = false
}

variable "is_global_trail" {
  default = true
}

variable "kinesis_arn" {
  type    = "string"
  default = ""
}

variable "prefix" {
  type = "string"
}

variable "s3_logging_bucket" {
  type = "string"
}
