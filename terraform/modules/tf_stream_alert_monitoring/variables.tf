variable "sns_topic_arn" {}

// Kinesis Stream name
variable "kinesis_stream" {
  type = "string"
}

// List of Lambda Function names
variable "lambda_functions" {
  type    = "list"
  default = []
}
