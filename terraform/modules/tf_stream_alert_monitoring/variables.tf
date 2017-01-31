variable "environments" {
  type = "list"

  default = [
    "staging",
    "production",
  ]
}

variable "sns_topic_arns" {
  type    = "list"
  default = []
}

variable "lambda_function_name" {}
