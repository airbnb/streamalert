variable "account_id" {}

variable "region" {}

variable "prefix" {}

variable "cluster" {}

variable "function_prefix" {}

variable "type" {}

variable "app_config_parameter" {}

variable "role_id" {}

variable "stream_alert_apps_config" {
  type    = "map"
  default = {}
}
