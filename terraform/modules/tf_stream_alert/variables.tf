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
  type    = "map"
  default = {}
}

variable "rule_processor_lambda_config" {
  type    = "map"
  default = {}
}

variable "rule_processor_versions" {
  type    = "map"
  default = {}
}

variable "alert_processor_config" {
  type    = "map"
  default = {}
}

variable "alert_processor_lambda_config" {
  type    = "map"
  default = {}
}

variable "alert_processor_versions" {
  type    = "map"
  default = {}
}

variable "output_lambda_functions" {
  type    = "map"
  default = {}
}

variable "output_s3_buckets" {
  type    = "map"
  default = {}
}

variable "input_sns_topics" {
  type    = "map"
  default = {}
}
