variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "function_role_id" {
  description = "Threat Intel Downloader function IAM Role ID, exported from the tf_lambda module"
}

variable "parameter_name" {
  default = "threat_intel_downloader_api_creds"
  type    = string
}

variable "monitoring_sns_topic" {
}

// ***** DynamoDB Table configuration *****

variable "table_rcu" {
  default = 10
}

variable "table_wcu" {
  default = 10
}

variable "max_read_capacity" {
  default = 5
}

variable "min_read_capacity" {
  default = 5
}

variable "target_utilization" {
  default = 70
}
