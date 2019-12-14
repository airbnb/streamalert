variable "prefix" {
  type = string
}

variable "cluster" {
  type = string
}

variable "event_pattern" {
  type    = string
  default = null
}

variable "kinesis_arn" {
  type = string
}
