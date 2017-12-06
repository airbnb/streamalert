variable "cluster" {
  type = "string"
}

variable "cross_account_ids" {
  type    = "list"
  default = []
}

variable "destination_stream_arn" {
  type = "string"
}

variable "enis" {
  type    = "list"
  default = []
}

variable "flow_log_filter" {
  default = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"
}

variable "flow_log_group_name" {
  type = "string"
}

variable "log_retention" {
  default = 365
}

variable "region" {
  type    = "string"
  default = "us-east-1"
}

variable "subnets" {
  type    = "list"
  default = []
}

variable "vpcs" {
  type    = "list"
  default = []
}
