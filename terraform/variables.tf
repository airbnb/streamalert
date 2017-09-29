variable "account" {
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

variable "stream_alert_apps_config" {
  type    = "map"
  default = {}
}

variable "alert_processor_versions" {
  type    = "map"
  default = {}
}

variable "aws-lambda" {
  type    = "map"
  default = {}
}

variable "aws-s3" {
  type    = "map"
  default = {}
}

variable "aws-sns" {
  type    = "map"
  default = {}
}

variable "clusters" {
  type    = "map"
  default = {}
}

variable "firehose" {
  type    = "map"
  default = {}
}

variable "flow_log_config" {
  type    = "map"
  default = {}
}

variable "kinesis_streams_config" {
  type    = "map"
  default = {}
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

variable "terraform" {
  type    = "map"
  default = {}
}
