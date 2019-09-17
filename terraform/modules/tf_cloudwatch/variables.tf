variable "prefix" {
  type = "string"
}

variable "cluster" {
  type = "string"
}

variable "kinesis_stream_arn" {
  type = "string"
}

variable "region" {
  type = "string"
}

variable "cross_account_ids" {
  type    = "list"
  default = []
}
