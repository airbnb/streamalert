variable "account_id" {}

variable "prefix" {}

variable "region" {}

variable "alerts_table_read_capacity" {}

variable "alerts_table_write_capacity" {}

variable "rules_table_read_capacity" {
  default = 5
}

variable "rules_table_write_capacity" {
  default = 5
}
