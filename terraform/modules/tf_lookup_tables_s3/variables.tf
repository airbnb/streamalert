variable "prefix" {
  description = "StreamAlert prefix"
  type        = "string"
}

variable "s3_buckets" {
  description = "A list of S3 bucket names to grant LookupTables access to. Cannot be empty!"
  type        = "list"
}

variable "roles" {
  description = "List of role ids to grant LookupTable access to"
  type        = "list"
}
