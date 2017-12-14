variable "buffer_size" {
  default = 5
}

variable "buffer_interval" {
  default = 300
}

variable "compression_format" {
  type    = "string"
  default = "GZIP"
}

variable "log_name" {
  type = "string"
}

variable "role_arn" {
  type = "string"
}

variable "s3_bucket_name" {
  type = "string"
}
