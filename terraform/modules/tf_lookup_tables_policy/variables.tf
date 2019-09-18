variable "prefix" {
  description = "StreamAlert prefix"
  type        = "string"
}

variable "roles" {
  description = "A list of role ids to grant LookupTable access to"
  type        = "list"
}

variable "policy_json" {
  description = "Full json document of the policy document"
  type        = "string"
}

variable "type" {
  description = "Type of access (e.g. s3 or dynamodb); used to suffix the policy name"
  type        = "string"
}
