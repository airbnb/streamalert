variable "account_id" {}

variable "region" {}

variable "prefix" {}

variable "rules_engine_timeout" {}

variable "use_prefix" {
  description = "When true, prepends the StreamAlert prefix to SQS resource name."
}
