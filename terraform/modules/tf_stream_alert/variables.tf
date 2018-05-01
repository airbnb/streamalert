variable "account_id" {
  default = ""
}

variable "cloudwatch_log_retention" {
  default = 14
}

variable "cluster" {
  type = "string"
}

variable "input_sns_topics" {
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

variable "prefix" {
  default = ""
}

variable "region" {
  default = ""
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

variable "rule_processor_metric_filters" {
  type    = "list"
  default = []
}

variable "rules_table_arn" {}

variable "sns_topic_arn" {}

variable "threat_intel_enabled" {
  default = false
}

variable "dynamodb_ioc_table" {
  default = "streamalert_threat_intel_ioc_table"
}
