variable "cluster" {}

variable "kinesis_stream_arn" {}

variable "region" {}

variable "cross_account_ids" {
  type    = "list"
  default = []
}
