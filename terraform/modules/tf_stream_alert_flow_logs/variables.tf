variable "destination_stream_arn" {}

variable "region" {
  default = "us-east-1"
}

variable "flow_log_group_name" {}

variable "targets" {
  type = "map"

  default = {
    "vpcs"    = []
    "subnets" = []
    "enis"    = []
  }
}

variable "flow_log_filter" {
  default = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"
}
