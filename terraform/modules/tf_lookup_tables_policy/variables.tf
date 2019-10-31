variable "prefix" {
  description = "StreamAlert prefix"
  type        = string
}

variable "roles" {
  description = "A list of role ids to grant LookupTable access to"
  type        = list(string)
}

variable "policy_json" {
  description = "Full json document of the policy document"
  type        = string
}

variable "type" {
  description = "Type of access (e.g. s3 or dynamodb); used to suffix the policy name"
  type        = string
}

// The below is only necessary becuase of:
//  https://github.com/hashicorp/terraform/issues/10857
// Fixed here: https://github.com/hashicorp/terraform/issues/12570#issuecomment-512621787
variable "role_count" {
  description = "Count of role ids to grant LookupTable access to. Note: this is a workaround until terraform v0.12.0 is supported"
}
