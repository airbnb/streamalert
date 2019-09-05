variable "dynamodb_tables" {
  description = "DynamoDb tables to grant LookupTable access to"
  type        = "list"
}

variable "s3_buckets" {
  description = "S3 buckets to grant LookupTable access to"
  type        = "list"
}

variable "roles" {
  description = "Role ids to grant LookupTable access to"
  type        = "list"
}

variable "account_id" {
  type = "string"
}

variable "region" {
  type = "string"
}

variable "prefix" {
  type = "string"
}