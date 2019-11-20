variable "bucket_name" {
  type = string
}

// Map of prefixes and suffixes
variable "filters" {
  type = list(map(string))
}

variable "lambda_function_alias_arn" {
  type = string
}

variable "lambda_function_name" {
  type = string
}

variable "lambda_function_alias" {
  default = "production"
}

variable "lambda_role_id" {
  type = string
}
