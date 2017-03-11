variable "environments" {
  type = "list"

  default = [
    "production"
  ]
}

variable "sns_topic_arns" {
  type    = "list"
  default = []
}

variable "lambda_function_name" {}
