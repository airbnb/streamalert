variable "lambda_source_bucket_name" {}

variable "lambda_source_key" {}

variable "lambda_handler" {}

variable "region" {}

variable "account_id" {}

variable "tfstate_s3_key" {}

variable "kms_key_alias" {}

variable "firehose_s3_bucket_suffix" {}

variable "prefix" {}

variable "output_lambda_source_key" {}

variable "lambda_function_prod_versions" {
  type    = "map"
  default = {}
}

variable "clusters" {
  type    = "map"
  default = {}
}

variable "kinesis_settings" {
  type    = "map"
  default = {}
}

variable "lambda_settings" {
  type    = "map"
  default = {}
}

variable "flow_log_settings" {
  type    = "map"
  default = {}
}
