variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "alerts_table_read_capacity" {
}

variable "alerts_table_write_capacity" {
}

variable "enable_rule_staging" {
  default = false
}

variable "rules_table_read_capacity" {
  default = 5
}

variable "rules_table_write_capacity" {
  default = 5
}

variable "rules_engine_timeout" {
  default = 300
}

variable "sqs_use_prefix" {
  default = false
}
