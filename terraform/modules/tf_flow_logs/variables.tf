variable "prefix" {
  type = "string"
}

variable "cluster" {
  type = "string"
}

variable "cloudwatch_logs_destination_arn" {
  type = "string"
}

variable "flow_log_filter" {
  default = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"
}

variable "log_retention" {
  default = 7
}

variable "enis" {
  type    = "list"
  default = []
}

variable "subnets" {
  type    = "list"
  default = []
}

variable "vpcs" {
  type    = "list"
  default = []
}
