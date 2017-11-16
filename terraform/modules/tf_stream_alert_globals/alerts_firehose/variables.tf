variable "account_id" {}

variable "buffer_size" {
  default = 128
}

variable "buffer_interval" {
  default = 300
}

variable "cloudwatch_log_retention" {
  default = 30
}

variable "compression_format" {
  default = "GZIP"
}

variable "prefix" {}

variable "region" {}
