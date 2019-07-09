variable "account_id" {}

variable "region" {}

variable "prefix" {}

variable "rules_engine_timeout" {}

variable "classifier_use_prefix" {
  description = "Allows support for multiple instances of StreamAlert on one account"
}