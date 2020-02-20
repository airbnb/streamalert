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

variable "compression_format" {
  type = string
}

variable "kms_key_arn" {
  type = string
}
