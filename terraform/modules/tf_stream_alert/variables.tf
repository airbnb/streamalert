variable "account_id" {
  default = ""
}

variable "region" {
  default = ""
}

variable "prefix" {
  default = ""
}

variable "cluster" {
  type = "string"
}

variable "kms_key_arn" {
  type = "string"
}

variable "rule_processor_config" {
  type = "map"
  default = {}
}

variable "rule_processor_lambda_config" {
  type = "map"
  default = {}
}

variable "rule_processor_prod_version" {
  type = "string"
}

variable "alert_processor_config" {
  type = "map"
  default = {}
}

variable "alert_processor_lambda_config" {
  type = "map"
  default = {}
}

variable "alert_processor_prod_version" {
  type = "string"
}
