variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "glue_catalog_db_name" {
  type        = string
  description = "Athena Database name"
}

variable "glue_catalog_table_name" {
  type        = string
  description = "Athena table name for Artifacts"
}

variable "s3_bucket_name" {
  type        = string
  description = "StreamAlert data bucket name"
}

variable "stream_name" {
  type        = string
  description = "Fully qualified name to use for delivery stream"
}

variable "buffer_size" {
  default = 5
}

variable "buffer_interval" {
  default = 300
}

variable "kms_key_arn" {
  type = string
}

variable "schema" {
  type = list(tuple([string, string]))
}
