variable "sns_topic_arn" {
}

variable "kinesis_alarms_enabled" {
  default = true
}

// Kinesis Stream name
variable "kinesis_stream" {
  type    = string
  default = ""
}

variable "lambda_alarms_enabled" {
  default = true
}

// List of Lambda Function names
variable "lambda_functions" {
  type    = list(string)
  default = []
}

// Lambda Invocation Error Alarm Settings

variable "lambda_invocation_error_threshold" {
  default = "0"
}

variable "lambda_invocation_error_evaluation_periods" {
  default = "1"
}

variable "lambda_invocation_error_period" {
  default = "300"
}

// Lambda Throttling Alarm Settings
variable "lambda_throttle_error_threshold" {
  default = "0"
}

variable "lambda_throttle_error_evaluation_periods" {
  default = "1"
}

variable "lambda_throttle_error_period" {
  default = "300"
}

// Lambda Iterator Age Alarm Settings
variable "lambda_iterator_age_error_threshold" {
  default = "1000000"
}

variable "lambda_iterator_age_error_evaluation_periods" {
  default = "1"
}

variable "lambda_iterator_age_error_period" {
  default = "300"
}

// Kinesis Iterator Age Alarm Settings
variable "kinesis_iterator_age_error_threshold" {
  default = "1000000"
}

variable "kinesis_iterator_age_error_evaluation_periods" {
  default = "1"
}

variable "kinesis_iterator_age_error_period" {
  default = "300"
}

// Kinesis Write Throughput Alarm Settings
variable "kinesis_write_throughput_exceeded_threshold" {
  default = "10"
}

variable "kinesis_write_throughput_exceeded_evaluation_periods" {
  default = "6"
}

variable "kinesis_write_throughput_exceeded_period" {
  default = "300"
}
