variable "account_id" {}

variable "prefix" {}

variable "region" {}

variable "kms_key_arn" {}

variable "alerts_table_read_capacity" {}

variable "alerts_table_write_capacity" {}

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
