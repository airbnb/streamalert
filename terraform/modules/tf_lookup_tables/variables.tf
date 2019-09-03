variable "dynamodb_tables" {
  description = "DynamoDb tables to grant LookupTable access to"
  type        = "list"
  default     = []
}

variable "s3_buckets" {
  description = "S3 buckets to grant LookupTable access to"
  type        = "list"
  default     = []
}

variable "account_id" {
  type = "string"
}

variable "region" {
  type = "string"
}