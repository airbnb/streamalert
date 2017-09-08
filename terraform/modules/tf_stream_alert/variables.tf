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

variable "rule_processor_log_level" {
  type    = "string"
  default = "info"
}

variable "rule_processor_enable_metrics" {
  default = false
}

variable "rule_processor_version" {}

variable "rule_processor_memory" {}

variable "rule_processor_timeout" {}

variable "alert_processor_config" {
  type    = "map"
  default = {}
}

variable "alert_processor_log_level" {
  type    = "string"
  default = "info"
}

variable "alert_processor_enable_metrics" {
  default = false
}

variable "alert_processor_version" {}

variable "alert_processor_memory" {}

variable "alert_processor_timeout" {}

variable "output_lambda_functions" {
  type    = "list"
  default = []
}

variable "output_s3_buckets" {
  type    = "list"
  default = []
}

variable "input_sns_topics" {
  type    = "list"
  default = []
}

variable "alert_processor_vpc_enabled" {
  default = false
}

variable "alert_processor_vpc_subnet_ids" {
  type    = "list"
  default = []
}

variable "alert_processor_vpc_security_group_ids" {
  type    = "list"
  default = []
}

variable "rule_processor_metric_filters" {
  type    = "list"
  default = []
}

variable "alert_processor_metric_filters" {
  type    = "list"
  default = []
}

variable "metric_alarms" {
  type    = "list"
  default = []
}

variable "namespace" {
  type    = "string"
  default = "StreamAlert"
}

variable "sns_topic_arn" {}
