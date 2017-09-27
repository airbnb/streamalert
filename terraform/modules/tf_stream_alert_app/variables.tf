variable "account_id" {}

variable "region" {}

variable "prefix" {}

variable "cluster" {}

variable "current_version" {}

variable "function_prefix" {}

variable "type" {}

variable "app_name" {}

variable "interval" {}

variable "app_memory" {}

variable "app_timeout" {}

variable "app_config_parameter" {}

variable "monitoring_sns_topic" {}

variable "stream_alert_apps_config" {
  type    = "map"
  default = {}
}

variable "log_level" {
  default = "info"
}
