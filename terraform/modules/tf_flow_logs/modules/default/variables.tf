variable "region" {
  type    = "string"
  default = "us-east-1"
}

variable "prefix" {
  type = "string"
}

variable "cluster" {
  type = "string"
}

variable "account_ids" {
  type    = "list"
  default = []
}

variable "destination_stream_arn" {
  type = "string"
}
