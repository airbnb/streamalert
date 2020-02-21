variable "prefix" {
  type = string
}

variable "cluster" {
  type = string
}

variable "destination_kinesis_stream_arn" {
  type = string
}

variable "regions" {
  type = list(string)
}
