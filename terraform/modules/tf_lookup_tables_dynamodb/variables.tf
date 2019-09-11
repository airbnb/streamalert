variable "dynamodb_tables" {
  description = "List of DynamoDB table names to grant LookupTable access to; Cannot be empty!"
  type        = "list"
}

variable "roles" {
  description = "List of role ids to grant LookupTable access to"
  type        = "list"
}

variable "account_id" {
  description = "AWS Account Id that the DynamoDB tables reside in"
  type        = "string"
}

variable "region" {
  description = "AWS Region that the DynamoDB tables reside in"
  type        = "string"
}
