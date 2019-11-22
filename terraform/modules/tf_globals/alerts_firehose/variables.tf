variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "buffer_size" {
  default = 128
}

variable "buffer_interval" {
  default = 300
}

variable "cloudwatch_log_retention" {
  default = 14
}

variable "compression_format" {
  default = "GZIP"
}

variable "kms_key_arn" {
  type = string
}

