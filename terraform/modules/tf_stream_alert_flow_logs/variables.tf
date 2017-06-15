variable "destination_stream_arn" {
  type = "string"
}

variable "region" {
  type    = "string"
  default = "us-east-1"
}

variable "flow_log_group_name" {
  type = "string"
}

variable "vpcs" {
  type    = "list"
  default = []
}

variable "subnets" {
  type    = "list"
  default = []
}

variable "enis" {
  type    = "list"
  default = []
}

variable "flow_log_filter" {
  default = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"
}
