variable "prefix" {
  type = string
}

variable "cluster" {
  type = string
}

variable "destination_kinesis_stream_arn" {
  type = string
}

variable "account_ids" {
  type = list(string)
}

// This is an output from the parent module
variable "cloudwatch_logs_subscription_role_arn" {
  type = string
}
