variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "bucket_name" {
  type = string
}

variable "buffer_size" {
  type = number
}

variable "buffer_interval" {
  type = number
}

variable "cloudwatch_log_retention" {
  type = number
}

variable "store_format" {
  type        = string
  description = "Either parquet or json"
}

variable "kms_key_arn" {
  type = string
}

variable "alerts_db_name" {
  type = string
}
