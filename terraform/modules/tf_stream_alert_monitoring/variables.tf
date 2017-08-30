variable "sns_topic_arn" {}

variable "kinesis_alarms_enabled" {
  default = true
}

// Kinesis Stream name
variable "kinesis_stream" {
  type    = "string"
  default = ""
}

variable "lambda_alarms_enabled" {
  default = true
}

// List of Lambda Function names
variable "lambda_functions" {
  type    = "list"
  default = []
}
