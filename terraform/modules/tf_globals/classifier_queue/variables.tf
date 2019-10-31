variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "rules_engine_timeout" {
}

variable "use_prefix" {
  description = "When true, prepends the StreamAlert prefix to SQS resource name."
}

