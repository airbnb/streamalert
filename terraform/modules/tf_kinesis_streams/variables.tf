variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "prefix" {
  type = string
}

variable "cluster" {
  type = string
}

variable "access_key_count" {
  default = 1
}

variable "create_user" {
  default = true
}

variable "trusted_accounts" {
  default = []
}

variable "retention" {
  default = 24
}

variable "stream_name" {
  type = string
}

variable "shards" {
  default = 1
}

// Default values for shard_level_metrics
variable "shard_level_metrics" {
  type    = list(string)
  default = []
}
